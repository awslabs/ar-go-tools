default: test

test:
	@./test.pl -e -p -c "../../cmd/gozer/gozer"

tests.log: ../test.pl test

show:
	@for dir in *; do \
		if [ -d "$$dir" ]; then \
			vim -o "$$dir/*.c" "$$dir/*.out"; \
		fi; \
	done;

clean:
	find -name '*.out' -execdir $(RM) '{}' \;
	$(RM) tests.log
