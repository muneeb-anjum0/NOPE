import subprocess


PASSWORD = "hardcoded-password"


def run_user_input(value):
    return subprocess.check_output(value, shell=True)
