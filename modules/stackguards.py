# 0CD - Quality of life utilities for obsessive compulsive CTF enthusiasts
# by b0bb (https://twitter.com/0xb0bb) and devx00
from __future__ import annotations

from binaryninja import (BackgroundTaskThread, Function,
                         Type, MediumLevelILOperation, Settings,
                         log_info, log_error, log_debug)
from binaryninja.types import PointerType
from abc import ABC, abstractmethod
from typing import Iterator


class ArchHandler(ABC):
    # Type name and definition for tcb
    struct_name: str = 'tcbhead_t'
    struct_definition: str | None = None

    @property
    def tcb_name(self) -> str:
        return Settings().get_string('0cd.stackguards.tcb_name')

    @property
    def var_name(self) -> str:
        return Settings().get_string('0cd.stackguards.var_name')

    def __init__(self, bv):
        self.bv = bv
        if self.struct_definition:
            self.bv.define_user_type(
                self.struct_name,
                self.struct_definition
            )

    def find_functions(self) -> Iterator[Function]:
        syms = filter(
            lambda sym: "__stack_chk_fail" in sym.name, self.bv.get_symbols())
        for sym in syms:
            for xref in self.bv.get_code_refs(sym.address):
                yield xref.function

    def set_guard_name(self, function) -> bool:
        log_debug(f'[*] Cleaning guard name for {function.name}')  # noqa: E501
        instrs = (ins for ins in function.mlil.instructions if ins.operation ==
                  MediumLevelILOperation.MLIL_SET_VAR)

        found = False
        for insn in instrs:
            for var in insn.vars_written:
                if ('stack_guard' in str(insn)
                        and self.struct_name in str(insn.vars_read)):
                    var.name = self.var_name
                    found = True

        return found

    @abstractmethod
    def set_tcb_struct(self, function: Function) -> bool:
        ...


class X86Handler(ArchHandler):
    src = 'gsbase'
    struct_definition = """
    struct __packed {
        void *tcb;
        void *dtv;
        void *self;
        int multiple_threads;
        long sysinfo;
        uintptr_t stack_guard;
        uintptr_t pointer_guard;
        int gscope_flag;
        int private_futex;
        void *__private_tm[5];
    };
    """

    def set_tcb_struct(self, function) -> bool:
        log_debug(f'[*] Cleaning tcb struct for {function.name}')  # noqa: E501
        instrs = (ins for ins in function.mlil.instructions if ins.operation ==
                  MediumLevelILOperation.MLIL_SET_VAR)

        found = False
        for insn in instrs:
            for var in insn.vars_read:
                if var.name == self.src and isinstance(var.type, PointerType):
                    vartype = Type.pointer(
                        self.bv.arch,
                        Type.named_type_from_registered_type(
                            self.bv, self.struct_name)
                    )
                    function.create_user_var(var, vartype, self.tcb_name)
                    found = True

        return found


class X64Handler(X86Handler):
    src = 'fsbase'
    struct_definition = """
    struct __packed {
        void *tcb;
        void *dtv;
        void *self;
        int multiple_threads;
        int gscope_flag;
        uint32_t sysinfo;
        uint32_t stack_guard;
        uint32_t pointer_guard;
        unsigned long int vgetcpu_cache[2];
        unsigned int feature_1;
        void *__private_tm[4];
        void *__private_ss;
        unsigned long long int ssp_base;
    };
    """


class Aarch64Handler(ArchHandler):
    struct_name = 'pthread'
    struct_definition = """
    struct __packed {
        uintptr_t dtv;
        void *unused;
        struct pthread *self;
        int multiple_threads;
        int gscope_flag;
        uintptr_t sysinfo;
        uintptr_t stack_guard;
        uintptr_t pointer_guard;
        uintptr_t unused2;
        uintptr_t unused3;
    };
    """

    def set_tcb_struct(self, function) -> bool:
        log_debug(f'[*] Cleaning tcb struct for {function.name}')  # noqa: E501
        instrs = (ins for ins in function.mlil.instructions if ins.operation ==
                  MediumLevelILOperation.MLIL_INTRINSIC and
                  'tpidr_el0' in str(ins))

        found = False
        for insn in instrs:
            for var in insn.vars_written:
                vartype = Type.pointer(
                    self.bv.arch,
                    Type.named_type_from_registered_type(
                        self.bv, self.struct_name)
                )
                function.create_user_var(var, vartype, self.tcb_name)
                found = True

        return found


supported = {
    'linux-x86': X86Handler,
    'linux-x86_64': X64Handler,
    'linux-aarch64': Aarch64Handler,
}


def get_arch_handler(platform) -> ArchHandler | None:
    if platform not in supported:
        supported_archs = ", ".join(supported.keys())
        log_error(
            f'[-] This plugin only supports the following platforms: {supported_archs}')  # noqa: E501
    return supported.get(platform, None)


def run_plugin_all(bv):

    if (handler := get_arch_handler(bv.platform.name)) is not None:
        targets = set(
            sym.address for sym in bv.get_symbols_by_name('__stack_chk_fail'))

        functions = set()
        for target in targets:
            for xref in bv.get_code_refs(target):
                functions.add(xref.function)

        task = StackGuardTask(handler(bv))
        task.start()


def run_plugin_current(bv, function):

    if (handler := get_arch_handler(bv.platform.name)) is not None:
        handler = handler(bv)
        task = StackGuardTask(handler, function)
        task.start()


class StackGuardTask(BackgroundTaskThread):

    def __init__(self, handler: ArchHandler, function: Function | None = None):
        BackgroundTaskThread.__init__(self, "Finding functions...", False)
        self.handler = handler
        self.function = function

    def run_with_functions(self, functions: list[Function]) -> bool:
        found = False
        n = len(functions)
        for i, function in enumerate(functions):
            self.progress = f'Cleaning tcb struct for function {function.name}... ({i}/{n})'  # noqa: E501
            found = self.handler.set_tcb_struct(function) or found

        self.handler.bv.update_analysis_and_wait()

        for i, function in enumerate(functions):
            self.progress = f'Cleaning guard variable for function {function.name}... ({i}/{n})'  # noqa: E501
            found = self.handler.set_guard_name(function) or found

        if found:
            self.progress = "Finished cleaning functions."
        else:
            self.progress = 'No stack guard functions found.'

        self.handler.bv.update_analysis_and_wait()
        return found

    def run(self):
        if self.function:
            self.run_with_functions([self.function])
            return

        functions = list(self.handler.find_functions())

        found = self.run_with_functions(functions)

        if found:
            log_info('[+] Stack guard functions cleaned successfully.')
            return

        log_info('[*] Retrying with  all functions.')
        functions = [
            fn for fn in self.handler.bv.functions if fn and fn.mlil]
        self.run_with_functions(functions)
