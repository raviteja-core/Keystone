package io.github.ravitejacore.keystone.autoconfigure.security;

import io.github.ravitejacore.keystone.autoconfigure.KeystoneProperties;
import io.github.ravitejacore.keystone.client.PermissionClient;
import io.github.ravitejacore.keystone.client.model.CheckRequest;
import io.github.ravitejacore.keystone.client.model.CheckResponse;
import io.github.ravitejacore.keystone.client.model.ResourceRef;
import io.github.ravitejacore.keystone.client.model.SubjectRef;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.DefaultParameterNameDiscoverer;
import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.lang.reflect.Method;
import java.util.Objects;

/**
 * Aspect enforcing @RequiresPermission annotations on Spring beans.
 * Evaluates SpEL expressions against method parameters and queries PermissionClient.
 * Guaranteed fail-closed behavior.
 */
@Aspect
public class RequiresPermissionAspect {

    private final PermissionClient permissionClient;
    private final KeystoneProperties properties;
    private final ExpressionParser parser = new SpelExpressionParser();
    private final ParameterNameDiscoverer parameterNameDiscoverer = new DefaultParameterNameDiscoverer();

    public RequiresPermissionAspect(PermissionClient permissionClient, KeystoneProperties properties) {
        this.permissionClient = Objects.requireNonNull(permissionClient, "permissionClient must not be null");
        this.properties = Objects.requireNonNull(properties, "properties must not be null");
    }

    @Around("@annotation(io.github.ravitejacore.keystone.autoconfigure.security.RequiresPermission) || @within(io.github.ravitejacore.keystone.autoconfigure.security.RequiresPermission)")
    public Object enforcePermission(ProceedingJoinPoint joinPoint) throws Throwable {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        RequiresPermission requiresPermission = method.getAnnotation(RequiresPermission.class);
        if (requiresPermission == null && joinPoint.getTarget() != null) {
            try {
                Method targetMethod = joinPoint.getTarget().getClass().getMethod(method.getName(), method.getParameterTypes());
                requiresPermission = targetMethod.getAnnotation(RequiresPermission.class);
            } catch (Exception ignored) {
            }
        }
        if (requiresPermission == null && joinPoint.getTarget() != null) {
            requiresPermission = joinPoint.getTarget().getClass().getAnnotation(RequiresPermission.class);
        }

        if (requiresPermission == null) {
            return joinPoint.proceed();
        }

        Object[] args = joinPoint.getArgs();

        EvaluationContext context = createEvaluationContext(method, args);

        String resourceType = evaluateSpel(requiresPermission.type(), context);
        String resourceId = evaluateSpel(requiresPermission.id(), context);
        String permission = requiresPermission.permission();

        SubjectRef subject = resolveSubject(requiresPermission.subject(), context);

        ResourceRef resource = ResourceRef.of(resourceType, resourceId);

        try {
            CheckResponse response = permissionClient.check(CheckRequest.of(resource, permission, subject));
            if (!response.allowed()) {
                throw new AccessDeniedException(
                    String.format("Access Denied: Subject %s:%s is not allowed '%s' on %s:%s",
                        subject.type(), subject.id(), permission, resource.type(), resource.id())
                );
            }
        } catch (AccessDeniedException e) {
            throw e;
        } catch (Exception e) {
            // FAIL CLOSED: Any communication failure, timeout, or backend error must result in AccessDeniedException
            throw new AccessDeniedException("Access Denied: Authorization service error during permission evaluation", e);
        }

        return joinPoint.proceed();
    }

    private EvaluationContext createEvaluationContext(Method method, Object[] args) {
        StandardEvaluationContext context = new StandardEvaluationContext();
        String[] paramNames = parameterNameDiscoverer.getParameterNames(method);
        if (paramNames != null) {
            for (int i = 0; i < paramNames.length; i++) {
                if (i < args.length) {
                    context.setVariable(paramNames[i], args[i]);
                }
            }
        }
        return context;
    }

    private String evaluateSpel(String expression, EvaluationContext context) {
        if (expression == null || expression.isBlank()) {
            return "";
        }
        if (expression.contains("#") || expression.startsWith("'") || expression.contains("T(") || expression.contains("+")) {
            try {
                Object val = parser.parseExpression(expression).getValue(context);
                return val != null ? val.toString() : "";
            } catch (Exception ignored) {
                // Fall back to literal if expression parsing fails
            }
        }
        return expression;
    }

    private SubjectRef resolveSubject(String subjectExpr, EvaluationContext context) {
        if (subjectExpr != null && !subjectExpr.isBlank()) {
            String subjectStr = evaluateSpel(subjectExpr, context);
            if (subjectStr.contains(":")) {
                String[] parts = subjectStr.split(":", 2);
                return new SubjectRef(parts[0], parts[1], null);
            }
            String defaultType = properties.getSubjectType() != null ? properties.getSubjectType() : "user";
            return new SubjectRef(defaultType, subjectStr, null);
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || authentication instanceof AnonymousAuthenticationToken) {
            throw new AccessDeniedException("Access Denied: Unauthenticated or anonymous user");
        }

        String sub = authentication.getName();
        if (authentication instanceof JwtAuthenticationToken jwtAuth) {
            Jwt jwt = jwtAuth.getToken();
            if (jwt.getSubject() != null && !jwt.getSubject().isBlank()) {
                sub = jwt.getSubject();
            }
        }

        String subjectType = properties.getSubjectType() != null ? properties.getSubjectType() : "user";
        return new SubjectRef(subjectType, sub, null);
    }
}
