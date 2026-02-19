/**
 * @name Unsafe deserialization of user input
 * @description User-controlled data flows into node-serialize's unserialize(),
 *              which can execute arbitrary code via serialized function objects.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id js/unsafe-deserialization
 * @tags security
 *       external/cwe/cwe-502
 */

import javascript
import DataFlow::PathGraph

class DeserializationSink extends DataFlow::Node {
  DeserializationSink() {
    exists(CallExpr call |
      call.getCalleeName() = "unserialize" and
      this = call.getArgument(0).flow()
    )
  }
}

class UnsafeDeserializationConfig extends TaintTracking::Configuration {
  UnsafeDeserializationConfig() { this = "UnsafeDeserializationConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof DeserializationSink
  }
}

from UnsafeDeserializationConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Untrusted data from $@ flows to node-serialize unserialize(), enabling remote code execution.",
  source.getNode(), "user input"
