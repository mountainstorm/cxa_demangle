#!/usr/bin/python
# coding: latin-1

# Copyright (c) 2012 Mountainstorm
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import _cxa_demangle
import pprint



#
# A basic representation of a C++ namespace/name component
#  name - the name e.g. 'std', 'boost', 'myfunc'
#  templateArgs - None or an array of CppType
#
class CppNameComponent:
	def __init__(self, name):
		self.name = name
		self.templateArgs = None


	def get_generalized_name(self):
		retVal = "%s" % self.name
		if self.templateArgs:
			retVal += "<"
			for idx, t in enumerate(self.templateArgs):
				retVal += "T%u" % idx
				if idx != len(self.templateArgs) - 1:
					retVal += ", "
			retVal += ">"		
		return retVal


	def __repr__(self):
		retVal = "%s" % self.name
		if self.templateArgs:
			retVal += "<"
			for idx, t in enumerate(self.templateArgs):
				retVal += t.__repr__()
				if idx != len(self.templateArgs) - 1:
					retVal += ", "
				elif len(t.components) > 1 and t.components[-1].templateArgs:
					retVal += " "
			retVal += ">"
		return retVal



#
# A basic representation of a C++ type
#  components - an array of CppNameComponent
#  qualifiers - None or an array of qualifiers e.g. '*', 'const', '&'
#
class CppType:
	def __init__(self):
		self.components = []
		self.qualifiers = None


	# value comparision just compares its value 
	def __eq__(self, other):
		retVal = False
		if isinstance(other, CppType):
			return self.get_generalized_name() == other.get_generalized_name()
		return retVal


	def __hash__(self):
		return hash(self.get_generalized_name())


	def get_generalized_name(self):
		retVal = ""
		for idx, c in enumerate(self.components):
			retVal += c.get_generalized_name()
			if idx != len(self.components) - 1:
				retVal += "::"
		return retVal


	def __repr__(self):
		retVal = ""
		for idx, c in enumerate(self.components):
			retVal += c.__repr__()
			if idx != len(self.components) - 1:
				retVal += "::"
		if self.qualifiers:
			for q in self.qualifiers:
				if q == "const":
					retVal += " "
				retVal += q
		return retVal



#
# Returned from getName
#  components - an array of CppNameComponent
#
class CppName:
	def __init__(self):
		self.components = []


	def get_generalized_name(self):
		retVal = ""
		for idx, c in enumerate(self.components):
			retVal += c.get_generalized_name()
			if idx != len(self.components) - 1:
				retVal += "::"
		return retVal


	def __repr__(self):
		retVal = ""
		for idx, c in enumerate(self.components):
			retVal += c.__repr__()
			if idx != len(self.components) - 1:
				retVal += "::"
		return retVal



#
# Returned by getFunctionSignature
#  returnType - None, or a CppType
#  arguments - an array of CppType
#  qualifiers - None or an array of qualifiers e.g. '*', 'const', '&'
#
class CppFunctionSignature:
	def __init__(self):
		self.returnType = None
		self.arguments = []
		self.qualifiers = None


	def __repr__(self):
		retVal = ""
		if self.returnType:
			retVal += self.returnType.__repr__() + " "

		retVal += "("
		for idx, a in enumerate(self.arguments):
			retVal += a.__repr__()
			if idx != len(self.arguments) - 1:
				retVal += ", "
		retVal += ")"
		if self.qualifiers:
			retVal += " "
			for q in self.qualifiers:
				retVal += q
		return retVal



#
# CppSymbol - represents a C++ symbol
#
class CxaDemangle:
	def __init__(self, name):
		# strip first character if an '_' if its got double _, probably everything been mangled
		if len(name) > 2 and name[0] == "_" and name[1] == "_":
			name = name[1:]

		demangle = _cxa_demangle._cxa_demangle(name)
		if demangle is None:
			raise ValueError("Invalid symbol name; probably not a C++ symbol")

		self.demangledName = demangle[0]
		self._root = demangle[1]


	# value comparision just compares its value 
	def __eq__(self, other):
		if isinstance(other, CppSymbol):
			return self.name == other.name 
		return False


	def __hash__(self):
		return hash(self.name)


	def is_function(self):
		return self._root["is_function"]


	def is_VTable(self):
		return self._root["type"] == "__vtable"


	def is_typeinfo(self):
		return self._root["type"] == "__typeinfo"


	def is_typeinfoName(self):
		return self._root["type"] == "__typeinfo_name"


	def is_ctor_dtor(self):
		return self._root["is_ctor_dtor_conv"]

	def is_VTT(self):
		return self._root["type"] == "__VTT"

	def is_construction_VTable(self):
		return self._root["type"] == "__construction_vtable"

	def is_non_virtual_thunk(self):
		return self._root["type"] == "__non_virtual_thunk"


	def is_virtual_thunk(self):
		return self._root["type"] == "__virtual_thunk"


	def get_name(self):
		retVal = CppName()
		state = [[retVal], retVal.components]

		self._get_name(self._root, state)
		return retVal


	def _get_name(self, node, state):
		if node is not None:
			type = node["type"]
			#print type
			if type == "__function":
				self._get_name(node["left"], state)

				if len(state) > 2:
					#print "func sig: "
					#print len(state), state
					sig = CppFunctionSignature()
					state[-1].append(sig)
					state.append([sig])
					state.append(sig.arguments)
					self._get_name(node["right"], state)
					state.pop()
					state.pop()
			elif type == "__function_signature":
				if node["left"]:
					sym = CppType()
					state.append([sym])
					state.append(sym.components)
					self._get_name(node["left"], state)
					state.pop()
					state.pop()
					state[-2][-1].returnType = sym
				
				# we have params ... so lets add one in to work on
				sym = CppType()
				state[-1].append(sym)
				state.append(sym.components)
				self._get_name(node["right"], state)
				state.pop()

			elif type == "__guard_variable":
				pass
			elif type == "__typeinfo":
				# typeinfo
				self._get_name(node["right"], state)
			elif type == "__typeinfo_name":
				# typeinfo name
				self._get_name(node["right"], state)
			elif type == "__VTT":
				# VTT
				self._get_name(node["right"], state)
			elif type == "__vtable":
				# vtable
				self._get_name(node["right"], state)
			elif type == "__non_virtual_thunk":
				# non virtual thunk
				self._get_name(node["right"], state)
			elif type == "__constructor":
				self._get_name(node["right"], state)
			elif type == "__destructor":
				self._get_name(node["right"], state)
				state[-1][-1].name = "~" + state[-1][-1].name
			elif type == "__construction_vtable":
				self._get_name(node["left"], state)
				self._get_name(node["right"], state)

			elif type == "__nested_delimeter":
				# variables - and perhaps other stuff; not a function
				self._get_name(node["left"], state)
				self._get_name(node["right"], state)
			elif type == "__cv_qualifiers":
				# if its root, we have a const/volatile function - check left.size
				self._get_name(node["left"], state)
				if len(state) > 2:
					# we only add const if its a type - not for a const func
					# we add that to the signature
					if state[-2][-1].qualifiers is None:
						state[-2][-1].qualifiers = []
					state[-2][-1].qualifiers.append("const")

			elif type == "__template_args":
				self._get_name(node["left"], state)
				#print state
				templateArgs = [CppType()]
				state[-1][-1].templateArgs = templateArgs
				state.append(templateArgs)
				state.append(templateArgs[0].components)
				self._get_name(node["right"], state)
				state.pop()
				state.pop()
				
			elif (	 type == "__source_name" 
				  or (len(type) >= len("__operator_") and type[:len("__operator_")] == "__operator_")):
				state[-1].append(CppNameComponent(node["name"]))
			elif (   type == "__std_qualified_name"
				  or type == "__sub_allocator"
				  or type == "__sub_basic_string"
				  or type == "__sub_string"):
				state[-1].append(CppNameComponent("std"))
				if len(node["name"]) > 5:
					state[-1].append(CppNameComponent(node["name"][5:]))

			elif type == "__sub":
				self._get_name(node["left"], state)
			elif type == "__list":
				self._get_name(node["left"], state)
				if node["right"]:
					state.pop()
					state[-1].append(CppType())
					state.append(state[-1][-1].components)
					self._get_name(node["right"], state)

			elif type == "__pointer_to":
				self._get_name(node["left"], state)
				if state[-2][-1].qualifiers is None:
					state[-2][-1].qualifiers = []
				state[-2][-1].qualifiers.append("*")

			elif type == "__pointer_to_member_type":
				#TODO: we should technically record what type this is a pointer to
				#self._get_name(node["left"], state)
				if state[-2][-1].qualifiers is None:
					state[-2][-1].qualifiers = []
				state[-2][-1].qualifiers.append("*")
				self._get_name(node["right"], state)

			elif type == "__lvalue_reference_to":
				self._get_name(node["left"], state)
				if state[-2][-1].qualifiers is None:
					state[-2][-1].qualifiers = []
				state[-2][-1].qualifiers.append("&")
			elif type == "__array":
				self._get_name(node["left"], state)
			else:
				if node["left"] == None and node["right"] == None:
					# leaf - must be a type
					state[-1].append(CppNameComponent(node["name"]))
				else:
					print type
					#pprint.pprint(self._root)
					raise ValueError


	def get_function_signature(self):
		retVal = None
		if self.is_function():
			retVal = CppFunctionSignature()
			state = [[retVal], retVal.arguments]
			self._get_function_signature(self._root, state)
		return retVal


	# note this look like the func above but is subtly different
	def _get_function_signature(self, node, state):
		if node is not None:
			type = node["type"]
			#print type
			if type == "__function":
				# its a function argument - it wont have a name but it
				# will have a sig
				#print len(state)
				if len(state) > 2:
					sig = CppFunctionSignature()
					state[-1].append(sig)
					state.append([sig])
					state.append(sig.arguments)
					self._get_function_signature(node["right"], state)
					state.pop()
					state.pop()
				else:
					self._get_function_signature(node["right"], state)
			elif type == "__function_signature":
				if node["left"]:
					sym = CppType()
					state.append([sym])
					state.append(sym.components)
					self._get_function_signature(node["left"], state)
					state.pop()
					state.pop()
					state[-2][-1].returnType = sym
				
				# we have params ... so lets add one in to work on
				sym = CppType()
				state[-1].append(sym)
				state.append(sym.components)
				self._get_function_signature(node["right"], state)
				state.pop()
				if len(state[-1][-1].components) == 0:
					# we didn;t add anything - its still empty i.e. there were no args
					state[-1].pop()
			elif type == "__non_virtual_thunk":
				# non virtual thunk
				self._get_function_signature(node["right"], state)
			elif type == "__constructor":
				self._get_function_signature(node["right"], state)
			elif type == "__destructor":
				self._get_function_signature(node["right"], state)
				
			elif type == "__nested_delimeter":
				# variables - and perhaps other stuff; not a function
				self._get_function_signature(node["left"], state)
				self._get_function_signature(node["right"], state)
			elif type == "__cv_qualifiers":
				# if its root, we have a const/volatile function - check left.size
				self._get_function_signature(node["left"], state)
				if state[-2][-1].qualifiers is None:
					state[-2][-1].qualifiers = []
				state[-2][-1].qualifiers.append("const")

			elif type == "__template_args":
				self._get_function_signature(node["left"], state)

				templateArgs = [CppType()]
				state[-1][-1].templateArgs = templateArgs
				state.append(templateArgs)
				state.append(templateArgs[0].components)
				self._get_function_signature(node["right"], state)
				state.pop()
				state.pop()
				
			elif (	 type == "__source_name" 
				  or (len(type) >= len("__operator_") and type[:len("__operator_")] == "__operator_")):
				state[-1].append(CppNameComponent(node["name"]))
			elif (   type == "__std_qualified_name"
				  or type == "__sub_allocator"
				  or type == "__sub_basic_string"
				  or type == "__sub_string"):
				state[-1].append(CppNameComponent("std"))
				if len(node["name"]) > 5:
					state[-1].append(CppNameComponent(node["name"][5:]))

			elif type == "__sub":
				self._get_function_signature(node["left"], state)
			elif type == "__list":
				if node["left"]:
					self._get_function_signature(node["left"], state)
				if node["right"]:
					state.pop()
					state[-1].append(CppType())
					state.append(state[-1][-1].components)
					self._get_function_signature(node["right"], state)

			elif type == "__pointer_to":
				self._get_function_signature(node["left"], state)
				#print state
				if state[-2][-1].qualifiers is None:
					state[-2][-1].qualifiers = []
				state[-2][-1].qualifiers.append("*")

			elif type == "__pointer_to_member_type":
				#TODO: we should technically record what type this is a pointer to
				#self._get_function_signature(node["left"], state)
				if state[-2][-1].qualifiers is None:
					state[-2][-1].qualifiers = []
				state[-2][-1].qualifiers.append("*")
				self._get_function_signature(node["right"], state)

			elif type == "__unresolved_name":
				#TODO: erm ... figure out what it actually is
				pass

			elif type == "__lvalue_reference_to":
				self._get_function_signature(node["left"], state)
				if state[-2][-1].qualifiers is None:
					state[-2][-1].qualifiers = []
				state[-2][-1].qualifiers.append("&")
			elif type == "__array":
				self._get_function_signature(node["left"], state)
			else:
				if node["left"] == None and node["right"] == None:
					# leaf - must be a type
					state[-1].append(CppNameComponent(node["name"]))
				else:
					print type
					#pprint.pprint(self._root)
					raise ValueError



if __name__ == "__main__":
	import sys
	import pprint

	#s = CxaDemangle"_ZTSN9ACE_SCOPE11ACE_RB_TreeIN9TAO_SCOPE3TAO9ObjectKeyEPNS2_20Refcounted_ObjectKeyENS2_19Less_Than_ObjectKeyENS_14ACE_Null_MutexEEE")
	#s = CxaDemangle"_ZN16EuPrimitiveTable14LoadValueTableERKSt6vectorIfSaIfEEi")
	#s = CxaDemangle"_ZNK13EuControlKnob22GetContainedPrimitivesERSt6vectorIP18EuPrimitiveControlSaIS2_EE")
	#s = CxaDemangle"_ZN17EuControlKnobCellD0Ev")
	#s = CxaDemangle"_ZN9TAO_SCOPE3TAO7details21load_protocol_factoryINS_25TAO_IIOP_Protocol_FactoryEEEiRN9ACE_SCOPE17ACE_Unbounded_SetIPNS_17TAO_Protocol_ItemEEEPKc")
	#s = CxaDemangle"_ZNK9TAO_SCOPE13TAO_Transport15sent_byte_countEv")
	#s = CxaDemangle"_ZN15CCircularBuffer11SetCopyFuncEPFPvS0_PKvmE")
	#s = CxaDemangle"_ZN5boost3_bi5list1IPFNS_3argILi1EEEvEEclINS_4_mfi3mf0IvSsEENS1_IRSsEEEEvNS0_4typeIvEERT_RT0_i")
	#s = CxaDemangle"_ZN5boost4bindIvSsPFNS_3argILi1EEEvEEENS_3_bi6bind_tIT_NS_4_mfi3mf0IS7_T0_EENS5_9list_av_1IT1_E4typeEEEMSA_FS7_vESD_")
	#s = CxaDemangle("_ZN5boost9function2INS_14iterator_rangeIN9__gnu_cxx17__normal_iteratorIPKcSsEEEES6_S6_SaINS_13function_baseEEEC2INS_9algorithm6detail13token_finderFINSD_10is_any_ofFIcEEEEEET_NS_11enable_if_cIXsrNS_11type_traits7ice_notIXsrNS_11is_integralISI_EE5valueEEE5valueEiE4typeE")
	#s = CxaDemangle("_ZNK11CEuDuration20ConvertToMacDurationEv")
	#print s.demangledName
	#pprint.pprint(s._root)	
	#print s.get_name()
	#print s.get_function_signature()
	#sys.exit(1)

	for line in sys.stdin.readlines():
		line = line.strip()
		if len(line) > 0:
			try:
				s = CxaDemangle(line)
				print s.demangledName
				try:
					print s.get_name(), s.get_function_signature()
				except:
					print s.name
					pprint.pprint(s._root)	
					raise ValueError
			except InvalidSymbolTypeError:
				pass
