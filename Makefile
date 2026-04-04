.PHONY: bump push upgrade clean

bump:
	uvx bump-my-version bump patch

push:
	git push --follow-tags

upgrade:
	uv tool upgrade pyvulscan

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
