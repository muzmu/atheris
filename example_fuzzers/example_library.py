# Copyright 2021 Fraunhofer FKIE
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


def func_2():
  func_3()
  return 2

def func_3():
  return 3

def func_1():
  func_2()
  return 1

def CodeBeingFuzzed(number):
  """Raises an exception if number is 17."""
  if number == 17:
    raise RuntimeError('Number was seventeen!')
  elif number == 1:
    func_1()
  elif number == 2:
    func_2()
  else:
    func_3()

