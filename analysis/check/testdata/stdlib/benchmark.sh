#!/bin/sh

find . -name "main.go" -type f | while read -r main_file; do
    dir=$(dirname "$main_file")
    echo "Running argot check in $dir"
    (cd "$dir" && timeout 5 argot check --summary summaries.yaml --via naive --config config.yaml main.go)
    if [ $? -eq 124 ]; then
        echo '{"timeout": true}' >"$dir/check-report.json"
        echo "Timeout in $dir"
    fi
done

aggregated_file="aggregated-report.json"
printf "{\n" >"$aggregated_file"
reports=$(find . -name "check-report.json" -type f | sort)
count=$(echo "$reports" | wc -l)
i=0
for report_file in $reports; do
    i=$((i + 1))
    dir=$(dirname "$report_file")
    test_name=$(basename "$dir")
    printf '  "%s": ' "$test_name" >>"$aggregated_file"
    cat "$report_file" >>"$aggregated_file"
    if [ $i -lt "$count" ]; then
        printf "," >>"$aggregated_file"
    fi
    printf "\n" >>"$aggregated_file"
done
printf "}\n" >>"$aggregated_file"

# autoformat
prettier -w "$aggregated_file"
