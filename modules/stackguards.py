# 0CD - Quality of life utilities for obsessive compulsive CTF enthusiasts
# by b0bb (https://twitter.com/0xb0bb) 

import os
import json
import binaryninja as bn

supported = [
    'linux-x86',
    'linux-x86_64',
]


def load_data(arch):
	current_file_path = os.path.dirname(os.path.abspath(__file__))
	data_db_path = os.path.join(current_file_path, '..', 'data/stackguards', arch+'.json')
	fh = open(data_db_path, 'r')
	return json.load(fh)


def check_arch(platform):
	if platform not in supported:
		bn.log_error('[-] This plugin only supports the following platforms: '+str(supported))
		return False

	return True


def run_plugin_all(bv):

	if check_arch(bv.platform.name):
		syms = list(filter(lambda sym: "__stack_chk_fail" in sym.name, bv.get_symbols()))
		if len(syms) == 0:
			return 0

		functions = set()
		for target in set(map(lambda sym: sym.address, syms)):
			for xref in bv.get_code_refs(target):
				functions.add(xref.function)

		data = load_data(bv.platform.name)
		task = StackGuardTask(bv, functions, data)
		task.start()


def run_plugin_current(bv, function):

	if check_arch(bv.platform.name):
		data = load_data(bv.platform.name)
		task = StackGuardTask(bv, [function], data)
		task.start()


class StackGuardTask(bn.BackgroundTaskThread):


	def __init__(self, bv, functions, data):
		bn.BackgroundTaskThread.__init__(self, "Finding functions...", False)
		self.bv = bv
		self.functions = functions
		self.data = data


	def run(self):

		self.bv.define_user_type('tcbhead_t', self.data['struct'])
		for function in self.functions:
			if self.set_guard_type(function):
				self.set_guard_name(function)


	def set_guard_type(self, function):

		for bb in function.medium_level_il:
			for insn in bb:
				if insn.operation != bn.MediumLevelILOperation.MLIL_SET_VAR:
					continue

				for var in insn.vars_read:
					if var.name == self.data['src'] and isinstance(var.type, bn.types.PointerType):
						vartype = bn.Type.pointer(
							self.bv.arch,
							bn.Type.named_type_from_registered_type(self.bv, 'tcbhead_t')
						)
						function.create_user_var(var, vartype, bn.Settings().get_string('0cd.stackguards.tcb_name'))
						self.bv.update_analysis_and_wait()
						return True

		return False


	def set_guard_name(self, function):

		for bb in function.medium_level_il:
			for insn in bb:
				if insn.operation != bn.MediumLevelILOperation.MLIL_SET_VAR:
					continue

				for var in insn.vars_written:
					if 'stack_guard' in str(insn) and 'tcbhead_t' in str(insn.vars_read):
						var.name = bn.Settings().get_string('0cd.stackguards.var_name')
						return True

		return False

