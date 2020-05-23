# Cisco ASA Syslogs Generator for Anomaly Detection

### Tool to generate dataset of syslogs containing security anomalies(possible attacks) and benign logs.

Syslog Generator is a tool to generate Cisco ASA system log messages. Generated messages can be either labelled or not, and can be generated from within seen or unseen message templates. Seen messages will be used to train machine learning models and unseen messages will be used to test how well machine learning models are trained and how good are they adapting to new, unseen variables.

Tool can be run by simple command from the tool's folder:

```
python syslog_generator.py
```

By default, generated dataset will contain 1000 messages, it will be labelled and  it will use only "seen" message templates. However, these arguments can be changed. There are three different arguments as following:

- --number <*number of lines*>; default *1000*
- --labelled <*yes/no*>; default *yes*
- --seen *<yes/no>*; default *yes*

So for example, unlabelled and unseen dataset of 25000 messages will be generated using following command:

```
python syslog_generator.py --number 25000 --labelled no --seen no
```

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
