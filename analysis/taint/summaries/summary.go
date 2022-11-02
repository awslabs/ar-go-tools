package summaries

// Summary summarizes taint-flow information for a function.
type Summary struct {
	// TaintingArgs is an array A that maps input argument positions to the arguments that are tainted
	// if the input argument is tainted. For example,  A[0] = [0,1] means that if the first argument
	// of the function is tainted, then when the function returns, the first and the last argument
	// are tainted.
	// A[1] = [] means that the second argument is sanitized.
	// A[1] = [1] means that the taint on the second argument is conserved, but no other argument is tainted.
	TaintingArgs [][]int
	// TaintingRets is an array A that links information between input arguments and outputs.
	// A[0] = [0] means that if argument 0 is tainted, then the first returned value is also tainted.
	TaintingRets [][]int
}
