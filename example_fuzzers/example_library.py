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
  if number % 17 > 9:
    i = 2
    if i == 2:
      i=12
      f2(number)
    if i == 12:
      i=14

def f2(number):
  if number == 48:
    i = 4
    if i == 4:
      i=13
      f3(number)
    if i == 13:
      i=12

def f3(number):
  if number == 48:
    i = 1
    if i == 1:
      i=2
    if i == 2:
      i=3
  raise RuntimeError('Number was found')


 

def CodeBeingFuzzed(number):
  """Raises an exception if number is 17."""
  if number % 17 > 5:
    #print("Number was 17")
    #raise RuntimeError('Number was seventeen!')
    i = 1
    f1(number)
    if i == 1:
      i=2
    if i == 2:
      i=3

  elif number == 12:
    i = 2
    f2(5)
    if i == 2:
      i=12
    if i == 12:
      i=14

    #print("Number was 12")
  elif number == 14:
    i = 4
    f3(17)
    if i == 4:
      i=13
    if i == 13:
      i=12

    #print("Number was 14")
  else:
    i=12
    #print("Number was somthing else")
