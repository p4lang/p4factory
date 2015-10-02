#!/usr/bin/env python
#
# Create a new P4 program target in the p4model repository

import os
import sys
import argparse

VERBOSE = False

def die(msg):
    """
    Error occurred; report and exit
    """
    sys.stderr.write(msg + "\n")
    exit(1)

def apply_subs_map(line, map):
    """
    Do string replacements on line indicated by map
    """
    for key, val in map.items():
        line = line.replace(key, val)
    return line

def copy_template(template_dir, filename, dest_dir, map):
    """
    Copy template to file dest_name with indicated string substitutions

    Remove first level of template_dir to form subdirectory for dest
    """
    if VERBOSE:
        print("create: %s + %s => %s" % (template_dir, filename, dest_dir))

    with open(os.path.join(template_dir, filename)) as f:
        content = f.readlines()

    # Allow substitutions in the filename as well as content
    dest_filename = os.path.join(dest_dir, apply_subs_map(filename, map))
    dest_dir = os.path.dirname(dest_filename)
    if not os.path.exists(dest_dir):
        os.mkdir(dest_dir)
    with open(os.path.join(dest_dir, dest_filename), "w") as f:
        for line in content:
            f.write(apply_subs_map(line, map))

def create_files(template_dir, dest_dir, proj_name):
    """
    Generate the files needed for the new target
    @param template_dir Where templates and dir structure are
    @param p4_source The file or directory holding P4 source code

    The directory 'template_dir' is scanned and a new version of each
    file there is created in the target directory.

    If template_dir is a directory, get everything there;
    If template_dir is a file, just get that file.
    """
    # The map of string replacements
    repl_map = { "__PROJECT_NAME__": proj_name }

    if os.path.isdir(template_dir):
        if template_dir[-1] != "/":
            template_dir = template_dir + "/"
        template_files = []
        for subdir, dirs, files in os.walk(template_dir):
            for file in files:
                filename = os.path.join(subdir, file).split(template_dir)[1]
                template_files.append(filename)
    elif os.path.isfile(template_dir):
        template_files = [os.path.basename(template_dir)]
        template_dir = os.path.dirname(template_dir)
    else:
        die("Could not find template dir %s" % template_dir)

    for source in template_files:
        copy_template(template_dir, source, dest_dir, repl_map)

def update_gitignore(path, name):
    with open(os.path.join(path, ".gitignore"), "a") as f:
        f.write(name + "\n")

def main():
    tools_dir = os.path.dirname(os.path.realpath(__file__))
    template_dir = os.path.join(tools_dir, "new_target_template")
    targets_dir = os.path.join(tools_dir, "../targets")
    modules_dir = os.path.join(tools_dir, "../modules")
    default_p4_prog = os.path.join(tools_dir, "default_p4_source")

    parser = argparse.ArgumentParser(
        description='Generate a new target for a P4 program',
        usage="%(prog)s [options] project-name")
    parser.add_argument('proj_name', metavar='proj_name', type=str,
                       help='The name of the project to generated')
    parser.add_argument('--p4_source', type=str,
                        help='The file or directory with P4 source to use',
                        default=os.path.join(tools_dir, default_p4_prog))
    parser.add_argument('--verbose', action="store_true",
                        help="Turn on verbose debugging", default=False)
    args = parser.parse_args()
    VERBOSE = args.verbose
    proj_name = args.proj_name.strip("/")

    if os.path.exists(proj_name):
        die("Directory or file %s exists" % proj_name)
    try:
        os.mkdir(os.path.join(targets_dir, proj_name))
        os.mkdir(os.path.join(targets_dir, proj_name, "p4src"))
        os.mkdir(os.path.join(targets_dir, proj_name, "tests"))
        os.mkdir(os.path.join(targets_dir, proj_name, "tests", "ptf-tests"))
        os.mkdir(os.path.join(targets_dir, proj_name, "targets"))
        os.mkdir(os.path.join(targets_dir, proj_name, "targets", "libpd_thrift"))
        os.mkdir(os.path.join(targets_dir, proj_name, "targets", "libtbl_packing"))
    except:
        die("Could not create directories for %s" % proj_name)

    create_files(template_dir, os.path.join(targets_dir, proj_name), proj_name)
    create_files(args.p4_source, os.path.join(targets_dir, proj_name, "p4src"),
                 proj_name)
    update_gitignore(modules_dir, "/%s_sim" % proj_name)

if __name__ == "__main__":
    main()
