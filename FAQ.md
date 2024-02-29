## Generating the SARIF output file is slow
 
This can occur is you are using the option `-g` and generate a SARIF file. The `-g` option
attempts to get the last commit for a file/line. In some case, git can be very slow and the
generation of the file can take a long time.

If you try to generate a SARIF file with the `-g` and have a slow file generation, consider
trying without the `-g` flag.


## I do not see an answer to my question

Please ask your question in the [discussions section](https://github.com/DataDog/datadog-static-analyzer/discussions).
