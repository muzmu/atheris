import cProfile
import re


cProfile.run("coverage run fuzzing_example.py -atheris_runs=$(ls ./ | wc -l)")

