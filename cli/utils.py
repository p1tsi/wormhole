def print_dict(d, indent=0):
    """Recursively prints a dictionary with indentation."""
    for key, value in d.items():
        print('\t' * indent + str(key) + ':', end=' ')
        if isinstance(value, dict):
            print()
            print_dict(value, indent + 1)
        elif isinstance(value, list):
            print()
            print_list(value, indent + 1)
        else:
            print(str(value))

def print_list(lst, indent=0):
    """Recursively prints a list with indentation."""
    for item in lst:
        if isinstance(item, dict):
            print_dict(item, indent)
        elif isinstance(item, list):
            print_list(item, indent + 1)
        else:
            print('\t' * indent + str(item))