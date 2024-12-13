# Syntactic Tool

The `syntactic` tool runs various syntactic analyses at the SSA level of the code.
All the syntactic analysis problems are grouped under the `syntactic-problems` category in a config file, and each category of syntactic problems will be listed separately.

## Struct Inits
Struct inits are a class of syntactic problem where the user can check that a specific struct type, e.g.  `crypto/tls.Config`, has fields that always have a specific value, for example `MinVersion` should always be `VersionTLS12`.
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
	no zero-allocations found
	no invalid writes to field MinVersion
[INFO]  Wrote final report in ???
```
The analyzer reports that 1) the struct was always allocated with the appropriate setting for the field `MinVersion` and 2) there were no writes that changed the value of that field to some value that is not capture by the constraints in the config file.