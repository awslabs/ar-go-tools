default: test

test:
	@./test.pl -s reachability -e -p -c "../../bin/reachability" reachable-functions
	@./test.pl -s panic -e -p -c "../../bin/maypanic" may-panic-analysis
	@./test.pl -s panic-model -e -p -c "../../bin/maypanic" may-panic-model-checking

#	@./test.pl -e -p -c "../../cmd/gozer/gozer"

tests.log: ./test.pl test

show:
	@for dir in *; do \
		if [ -d "$$dir" ]; then \
			vim -o "$$dir/*.c" "$$dir/*.out"; \
		fi; \
	done;

clean:
	find . -name '*.out' -execdir $(RM) '{}' \;
	$(RM) tests.log
	$(RM) tests-*.log
