package summaries

// requiredSummaries contains a list of functions that need to be analyzed for the analysis to build a sound model
// of the program.
// For example, (*sync.Once).Do needs to be summarized because it will call its argument. Stubbing out Do.Once would
// only model the flow of data but not the callgraph.
var requiredSummaries = map[string]bool{
	"(*sync.Once).Do":     true,
	"(*sync.Once).doSlow": true,
}
