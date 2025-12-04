.PHONY: run venv-check

# Check if venv exists and warn if not active
venv-check:
	@test -d .venv || (echo "Error: .venv directory not found" && exit 1)
	@if [ -z "$$VIRTUAL_ENV" ] || [ "$$VIRTUAL_ENV" != "$$(pwd)/.venv" ]; then \
		echo "Note: Virtual environment not active, will activate for run target"; \
	else \
		echo "Virtual environment already active"; \
	fi

# Run the web app, activating venv if needed
run: venv-check
	@if [ -z "$$VIRTUAL_ENV" ] || [ "$$VIRTUAL_ENV" != "$$(pwd)/.venv" ]; then \
		. .venv/bin/activate && python web_app.py; \
	else \
		python web_app.py; \
	fi
