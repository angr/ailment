
import os
import subprocess
from tempfile import TemporaryDirectory


def solve_types(facts):
    return solve(facts, 'types.dl', ['has_type'])


def solve(facts, dl_file, output_relations):
    my_loc = os.path.dirname(os.path.realpath(__file__))
    dl_file_path = os.path.join(my_loc, dl_file)
    with TemporaryDirectory() as td:
        for name, facts_list in facts.items():
            file_contents = '\n'.join(','.join(f) for f in facts_list)
            tmp_file_name = os.path.join(td, '{}.facts'.format(name))
            with open(tmp_file_name, 'w') as f:
                f.write(file_contents)
        subprocess.run(['souffle', '-F', td, '-D', td, dl_file_path], check=True)
        result = {}
        for orel in output_relations:
            with open(os.path.join(td, '{}.csv'.format(orel)), 'r') as f:
                result[orel] = [l.split(',') for l in f.read().splitlines()]
        return result
