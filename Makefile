.PHONY: testbed testbed-down testbed-render testbed-day2 labels

CONFIG ?= C1
TRAFFIC ?= ping

testbed:
	bash testbed/run.sh $(CONFIG) $(TRAFFIC)

testbed-day2:
	bash testbed/run_day2.sh

labels:
	python3 testbed/labels.py

testbed-down:
	@if docker info >/dev/null 2>&1; then \
	  docker compose -f testbed/docker-compose.yml down --remove-orphans; \
	elif sudo docker info >/dev/null 2>&1; then \
	  sudo docker compose -f testbed/docker-compose.yml down --remove-orphans; \
	else \
	  echo "docker not available"; exit 1; \
	fi

testbed-render:
	python3 testbed/render.py $(CONFIG)
