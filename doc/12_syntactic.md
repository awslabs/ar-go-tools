# Syntactic Tool

The `syntactic` tool runs various syntactic analyses at the SSA level of the code.
All the syntactic analysis problems are grouped under the `syntactic-problems` category in a config file, and each category of syntactic problems will be listed separately.

## Struct Inits
When you want to check that a specific struct type's fields are always given a specific value, you can specify it in a `struct-inits` problem. For example, if you may want to check that the field `MinVersion` of `crypto/tls.Config` is always set to the constant `VersionTLS12`. Note that we do not have a check to ensure the field's value is always the desired constant; we only check that syntactically, the assignments are valid.
One would write this analysis by adding in the config the following:
```yaml
syntactic-problems:
  struct-inits:
    - tag: "check-min-version-is-1.2"
      description: "This checks that the MinVersion in the tls.Config is always 1.2"
      struct: # Defines the struct of interest
        type: "crypto/tls.Config" # specify the struct type
      fields-set: # Defines the fields of interest, and the value they should be set to
        - field: "MinVersion" # The field
          value: # The value, a code identifier: package + const or package + method
            package: "crypto/tls"
            const: "VersionTLS12"
      filters: # Some function where we don't want reports, typically dependencies
        - package: "some-dep/*"
          method: ".*"
```
Once you have a configuration file, you can run `argot syntactic -config config.yaml ...`.
If there are no improper initializations, or improper values being assigned to the fields you are checking, the output should look like:
```shell
[INFO]  Loaded ? annotations from program
[INFO]  Gathering values and starting pointer analysis...
[INFO]  Pointer analysis terminated (?? s)
[INFO]  starting struct init analysis...
[INFO]  Analyzing ???? unfiltered reachable functions...
[INFO]
struct-init analysis results:
-----------------------------
initialization information for crypto/tls.Config:
	no incomplete initializations found
	no invalid writes to field MinVersion
[INFO]  Wrote final report in ???
```
The analyzer reports that 1) the struct was always initialized with the appropriate setting for the field `MinVersion` and 2) there were no writes that changed the value of that field to some value that is not capture by the constraints in the config file.

If the struct was initialized without setting a value for the `MinVersion` field, the analyzer will report it as an "incomplete initialization" because the field is implicitly set to its zero value.

> ⚠ The `struct-inits` checks only check that the struct of concern is 1) always initialized with a non-zero value for all the fields specified in `fields` and 2) all writes to the field in `fields` are writing the `value` specified. This is not a check that ensures the field's value is always the value in values.

### Must-reinits

Sometimes the bad struct initialization is in a dependency that you cannot modify. To silence the alert, you need to add the dependency's function where the struct is badly initialized to the `filters` of the struct-init problem. However, you have to remember to reinitialize the struct: while Argot would check that all field assignment are correct with respect to the config above, it would not check that the fields have been reassigned. To perform that check, you need to add a `must-reinit` specification:
```yaml
syntactic-problems:
  struct-inits:
    - tag: "check-min-version-is-1.2"
      description: "This checks that the MinVersion in the tls.Config is always 1.2"
      struct: # Defines the struct of interest
        type: "crypto/tls.Config" # specify the struct type
      fields-set: # Defines the fields of interest, and the value they should be set to
        - field: "MinVersion" # The field
          value: # The value, a code identifier: package + const or package + method
            package: "crypto/tls"
            const: "VersionTLS12"
      filters: # Some function where we don't want reports, typically dependencies
        - package: "some-dep/.*"
          method: "generateTlsConfig"
      must-reinit: # Findings in some function bodies are silenced, but we must check the results are reinitialized
        - package: "some-dep/.*"
          method: "generateTlsConfig" # enforce fields of the struct returned by this call are reinitialized
```
In the example above, provided `generateTlsConfig` is a function that outputs a struct of type `crypto/tls.Config` (or a pointer to it), then Argot will check that when `generateTlsConfig` is called, then the field `MinVersion` is reassigned immediately after the function is called.
For example, this code snippet will pass the check:
```go
config := dependency.generateTlsConfig()
config.MinVersion = tls.VersionTLS12
```
but this will not pass:
```go
config := dependency.generateTlsConfig()
handleConfig(config)
config.MinVersion = tls.VersionTLS12
```
because the fields MUST be reinitialized in the same block as the call to the function, and immediately after. If any other instruction precedes the field assignment, Argot will generate a finding. In particular, assigning other fields should be done after having assigned the fields that are tracked by the `struct-init` problem for which `must-reinit` is specified.

## Precondition Checks
Users may want to check that some specific functions are called only when some precondition is satisfied. You can specify a `cond-check` constraint in the config file in the `syntactic-problems` to check for those properties. Currently, the analysis is limited to checking that specific functions are called only when some simple precondition on the output of another function is called. The function calls in the preconditions must be static calls: we currently do not support interfaces.

For example, the following specification lets you check that `FooFunc` of the `func-cond` package is only called when `FooPreCheck(...)` holds, or the first boolean output of `ResourceCheck(...)` is true and the second output (of type `error`) is `nil`. Currently, the syntax is very limited, we use the string representation of the SSA form.
```yaml
syntactic-problems:
  cond-checks:
    - tag: funcCond
      # Calling Foo requires FooPreCheck
      call:
        - method: ^FooFunc$
          package: func-cond$
      preconditions: # either guard must hold when calling the function in call
        - precondition: ["!(ResourceCheck(...)#1 != nil:error)", "ResourceCheck(...)#0"]
        - precondition: ["FooPreCheck(...)"]
```
- `call` is a list of code identifiers, here only `method` and `package` specifications are supported.
- `preconditions` is a list of preconditions. The analysis checks that for every call described by one of the identifiers in call, then *one of* the preconditions holds on *all control-flow paths* from the function entry point to the identified call.
> Currently, each precondition is a list of conjuncts in string format. Each conjunct is a simple expression with function calls where arguments are replaced by ellipsis `f(...)`, tuple-extraction (`#0` is the first element of the tuple) and basic unary and binary operators. We will improve on handling properly expression syntax, and for now we recommend using the output of the analysis with findings to write those conditions. When the path condition of a call does not satisfy some precondition, then its expression is printed on the command line. Break down the expression by separating the conjuncts to get the precondition for the config file.

When some call does not satisfy the preconditions, an error message is printed:
```
[ERROR] Preconditions not satisfied in call FooFunc(struct{x int}{}:G)
[ERROR] Preconditions is: !(FooPreCheck(...))
[ERROR] Position: /<>/analysis/syntactic/preconditions/testdata/func-cond/main.go:56:9
```
The positions are also printed when the analysis terminates.

If the analysis doesn't detect any invalid calls, you should see the message:
```
[INFO]
precondition analysis results:
-----------------------------
all calls have valid preconditions!
```
