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

def f1(number):
  if number == 12:
    i = 2
  f2(11)

def f2(number):
  i=12
  f3(i)

def f3(number):
  i=13
  return 1
 

def CodeBeingFuzzed(number):
  """Raises an exception if number is 17."""
  if number == 17:
    #print("Number was 17")
    f1(12)
    raise RuntimeError('Number was seventeen!')
    #print("Number was somthing else")
