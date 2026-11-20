package io.github.ravitejacore.keystone.autoconfigure.security;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Declarative method-level ReBAC authorization annotation.
 * Evaluates reachability over Keystone's relationship graph before method execution.
 *
 * <pre>
 * &#64;GetMapping("/docs/{id}")
 * &#64;RequiresPermission(type = "doc", id = "#id", permission = "view")
 * public Doc getDoc(@PathVariable String id) { ... }
 * </pre>
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface RequiresPermission {

    /**
     * Target resource type (e.g. "doc", "folder", or SpEL).
     */
    String type();

    /**
     * Target resource ID, supporting Spring Expression Language (SpEL) referencing method arguments (e.g. "#id").
     */
    String id();

    /**
     * Required permission to check on the target resource (e.g. "view", "edit", "delete").
     */
    String permission();

    /**
     * Optional subject reference or SpEL expression.
     * When left empty (default), the subject is automatically resolved to the authenticated user's JWT "sub" claim.
     */
    String subject() default "";
}
