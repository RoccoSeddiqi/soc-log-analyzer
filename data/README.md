# Data Directory

This directory contains sample log files used for development and testing.

The attack-related log samples are derived from publicly available
datasets provided by the Security Datasets projects:
https://securitydatasets.com/
https://github.com/splunk/attack_data

Specific Datasets: 
    Windows Datasets: 
        Execution: 
        https://securitydatasets.com/notebooks/atomic/windows/execution/SDWIN-201029001615.html

        Credential Access:
        https://securitydatasets.com/notebooks/atomic/windows/credential_access/SDWIN-190518202151.html

        Persistence: 
        https://securitydatasets.com/notebooks/atomic/windows/persistence/SDWIN-190319024742.html

    Linux Datasets: 
        Discovery:
        https://securitydatasets.com/notebooks/atomic/linux/discovery/SDLIN-201110074812.html

        Defense Evasion:
        https://securitydatasets.com/notebooks/atomic/linux/defense_evasion/SDLIN-201110081941.html

Datasets are trimmed and simplified to support rapid testing of the
detection pipeline.

example_attack.json <-- has attack
example_normal.json <-- attack has been removed