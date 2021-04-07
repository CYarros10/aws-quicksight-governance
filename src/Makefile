.PHONY: bundle
bundle:
	rm -rf ./python && mkdir -p ./python
	find . -type d -name __pycache__ -exec rm -r {} \+
	pip install requests --target ./python
	zip -v -r9 requests.zip python/

.PHONY: clean
clean:
	rm -rf python/ requests.zip