/**
 * @name ECB mode encryption
 * @description AES in ECB mode does not provide semantic security.
 *              Identical plaintext blocks produce identical ciphertext blocks.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id js/ecb-mode-encryption
 * @tags security
 *       external/cwe/cwe-327
 */

import javascript

from CallExpr call, string algo
where
  (
    call.getCalleeName() = "createCipher" or
    call.getCalleeName() = "createCipheriv" or
    call.getCalleeName() = "createDecipher" or
    call.getCalleeName() = "createDecipheriv"
  ) and
  algo = call.getArgument(0).(StringLiteral).getValue() and
  algo.regexpMatch(".*ecb.*")
select call, "Using ECB mode encryption ('" + algo + "'). ECB does not hide data patterns — use CBC or GCM instead."
