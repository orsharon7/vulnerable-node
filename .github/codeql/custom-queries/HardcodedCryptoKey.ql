/**
 * @name Hardcoded cryptographic key
 * @description Finds hardcoded encryption keys and secrets in source code.
 *              Hardcoded keys make it trivial for attackers to decrypt data.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @id js/hardcoded-crypto-key
 * @tags security
 *       external/cwe/cwe-798
 *       external/cwe/cwe-321
 */

import javascript

from VariableDeclarator vd, string name
where
  name = vd.getBindingPattern().(VarDecl).getName() and
  (
    name.regexpMatch("(?i).*(secret|key|token|password|credential|api.?key).*") and
    exists(StringLiteral s | s = vd.getInit() | s.getValue().length() > 8)
  )
select vd, "Hardcoded secret in variable '" + name + "'. Use environment variables or a secrets manager instead."
