- complete guide to cuckoo sandbox guide:
    ```python
    complete-guide-cuckoo.md
    ```

- simple python script to add yara rules in cuckoo sandbox:
   ```python

    # default dir is ~.cuckoo/yara/
    # default url: 'https://github.com/Yara-Rules/rules/archive/master.zip'
    example with default config:  python3 yara-rules.py
   ```
- available options:
-d, --dir change default dir for yara rules
-l, --list setup another url for yara rules repository, can be multi-urls
    ```python
      python3 yara-rules.py --dir MYDIR/.cuckoo/yara/ --list https://github.com/Yara-Rules/rules/archive/master.zip any-other-URL
    ```

