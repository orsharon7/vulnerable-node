/**
 * @name Sensitive data written to temporary file
 * @description Writing passwords, tokens, or session data to /tmp files
 *              makes them accessible to other users on the system.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision high
 * @id js/sensitive-temp-file
 * @tags security
 *       external/cwe/cwe-312
 *       external/cwe/cwe-377
 */

import javascript

from CallExpr call, StringLiteral pathArg
where
  (
    call.getCalleeName() = "writeFileSync" or
    call.getCalleeName() = "writeFile"
  ) and
  pathArg.getValue().regexpMatch(".*/tmp/.*") and
  (
    call.getArgument(0).flow().getALocalSource() = pathArg.flow() or
    call.getArgument(0).(StringLiteral) = pathArg
  )
select call, "Writing potentially sensitive data to temporary file '" + pathArg.getValue() + "'. Temp files may be readable by other users."
