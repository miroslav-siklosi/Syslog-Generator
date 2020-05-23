# Cisco ASA Syslogs Generator for Anomaly Detection

Tool to generate dataset of syslogs containing security anomalies(possible attacks) and benign logs.

### Prerequisites

Use `pip install Faker` to Python library Faker.

### Generating dataset

1. Specify number of logs  to generate by changing `number` in `logs = generate_logs(number, True)` with desired integer. If you want to generate labelled dataset, choose `True`, otherwise choose `False`.
2. Run the script to generate syslogs.

### Author
- Miroslav Siklosi

### License
This project is licensed under the MIT License - see the LICENSE.md file for details

### Acknowledgments

- [Faker library](https://faker.readthedocs.io/en/master/)
