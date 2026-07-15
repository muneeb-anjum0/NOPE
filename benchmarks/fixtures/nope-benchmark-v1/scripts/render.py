import subprocess


def render(user_template):
    return subprocess.check_output("wkhtmltopdf " + user_template, shell=True)
