.PHONY: os0-image os0-repro os0-smoke os0-test phase7-test

os0-image:
	python3 os/os0/build.py --output build/os0

os0-repro:
	python3 os/os0/build.py --output build/os0 --verify

os0-smoke: os0-image
	python3 os/os0/smoke.py --images build/os0

os0-test:
	python3 -m unittest discover -s os/os0 -p 'test_*.py'

phase7-test:
	python3 -m unittest -v services.phase7.test_phase7
