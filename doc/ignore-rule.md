## Ignoring a rule


> [!NOTE]
> TL;DR: use the command `dd-no-sa` to ignore a rule


### Ignoring all results in a file

To ignore all rules in a file, put `no-dd-sa` in a comment
on the **first line** of the file.

In the following code snippet, all rules are ignored in the file.

```python
#no-dd-sa
def foo():
  print("foo: {}".format("bar"))
```



### Ignoring a list of rules in a file

To ignore all rules in a file, put `no-dd-sa` followed
by the list of rules to ignore in a comment
on the **first line** of the file.

In the following code snippets, the rules `python-best-practices/rule1`
and `python-best-practices/rule2` will be ignored for the file, all
other rules will apply.

```python
#no-dd-sa python-best-practices/rule1 python-best-practices/rule2
def foo():
  print("foo: {}".format("bar"))
```


### Ignoring a list of rules on a specific line

To ignore rules on a specific line, put `no-dd-sa` followed
by the list of rules to ignore in a comment on the **line above** 
the one you want to ignore.

```python
def foo():
  #no-dd-sa python-best-practices/rule1 python-best-practices/rule2
  print("foo: {}".format("bar"))
```


### Ignoring all rules on a specific line

To ignore all rules on a specific line, put `no-dd-sa` on the **line above**
the one you want to ignore.

```python
def foo():
  #no-dd-sa
  print("foo: {}".format("bar"))
```
