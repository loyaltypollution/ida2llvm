import ida_idaapi
import ida_kernwin
import idautils
import ida_name
import ida_funcs
import ida_segment

from PySide6 import QtCore, QtWidgets
from PySide6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont

class LLVMSyntaxHighlighter(QSyntaxHighlighter):
    """
    Syntax highlighter for LLVM IR.
    """
    def __init__(self, document):
        super().__init__(document)
        
        # Define formats
        self.keyword_format = QTextCharFormat()
        self.keyword_format.setForeground(QColor(0, 0, 255))  # Blue
        self.keyword_format.setFontWeight(QFont.Weight.Bold)
        
        self.type_format = QTextCharFormat()
        self.type_format.setForeground(QColor(0, 128, 128))  # Teal
        
        self.function_format = QTextCharFormat()
        self.function_format.setForeground(QColor(128, 0, 128))  # Purple
        self.function_format.setFontWeight(QFont.Weight.Bold)
        
        self.comment_format = QTextCharFormat()
        self.comment_format.setForeground(QColor(0, 128, 0))  # Green
        self.comment_format.setFontItalic(True)
        
        self.string_format = QTextCharFormat()
        self.string_format.setForeground(QColor(163, 21, 21))  # Dark red
        
        self.number_format = QTextCharFormat()
        self.number_format.setForeground(QColor(255, 127, 0))  # Orange
        
        self.label_format = QTextCharFormat()
        self.label_format.setForeground(QColor(139, 69, 19))  # Brown
        self.label_format.setFontWeight(QFont.Weight.Bold)
        
        # LLVM keywords
        self.keywords = [
            'define', 'declare', 'target', 'datalayout', 'triple', 'ret', 'br',
            'switch', 'indirectbr', 'invoke', 'resume', 'unreachable', 'add',
            'fadd', 'sub', 'fsub', 'mul', 'fmul', 'udiv', 'sdiv', 'fdiv',
            'urem', 'srem', 'frem', 'shl', 'lshr', 'ashr', 'and', 'or', 'xor',
            'alloca', 'load', 'store', 'getelementptr', 'inbounds', 'trunc',
            'zext', 'sext', 'fptrunc', 'fpext', 'fptoui', 'fptosi', 'uitofp',
            'sitofp', 'ptrtoint', 'inttoptr', 'bitcast', 'addrspacecast',
            'icmp', 'fcmp', 'phi', 'select', 'call', 'va_arg', 'landingpad',
            'catchpad', 'cleanuppad', 'eq', 'ne', 'ugt', 'uge', 'ult', 'ule',
            'sgt', 'sge', 'slt', 'sle', 'oeq', 'ogt', 'oge', 'olt', 'ole',
            'one', 'ord', 'ueq', 'une', 'uno', 'to', 'nuw', 'nsw', 'exact',
            'volatile', 'atomic', 'unordered', 'monotonic', 'acquire', 'release',
            'acq_rel', 'seq_cst', 'private', 'internal', 'external', 'weak',
            'linkonce', 'common', 'appending', 'extern_weak', 'linkonce_odr',
            'weak_odr', 'dllimport', 'dllexport', 'align', 'gc', 'null',
            'undef', 'true', 'false', 'global', 'constant', 'entry'
        ]
        
        # LLVM types
        self.types = [
            'void', 'i1', 'i8', 'i16', 'i32', 'i64', 'i128',
            'float', 'double', 'x86_fp80', 'fp128', 'ppc_fp128',
            'label', 'metadata', 'type', 'opaque'
        ]
    
    def highlightBlock(self, text):
        # Highlight keywords
        for keyword in self.keywords:
            import re
            pattern = r'\b' + keyword + r'\b'
            for match in re.finditer(pattern, text):
                self.setFormat(match.start(), match.end() - match.start(), 
                              self.keyword_format)
        
        # Highlight types
        for type_word in self.types:
            import re
            pattern = r'\b' + type_word + r'\b'
            for match in re.finditer(pattern, text):
                self.setFormat(match.start(), match.end() - match.start(),
                              self.type_format)
        
        # Highlight type patterns (i8*, [100 x i32], etc.)
        import re
        type_patterns = [
            r'i\d+\*?',
            r'\[\d+ x [^\]]+\]',
            r'<\d+ x [^>]+>',
        ]
        for pattern in type_patterns:
            for match in re.finditer(pattern, text):
                self.setFormat(match.start(), match.end() - match.start(),
                              self.type_format)
        
        # Highlight comments
        import re
        comment_pattern = r';[^\n]*'
        for match in re.finditer(comment_pattern, text):
            self.setFormat(match.start(), match.end() - match.start(),
                          self.comment_format)
        
        # Highlight strings
        import re
        string_pattern = r'"[^"\\]*(\\.[^"\\]*)*"'
        for match in re.finditer(string_pattern, text):
            self.setFormat(match.start(), match.end() - match.start(),
                          self.string_format)
        
        # Highlight numbers
        import re
        number_pattern = r'\b-?\d+\.?\d*\b'
        for match in re.finditer(number_pattern, text):
            self.setFormat(match.start(), match.end() - match.start(),
                          self.number_format)
        
        # Highlight labels
        import re
        label_pattern = r'^\s*\w+:'
        for match in re.finditer(label_pattern, text, re.MULTILINE):
            self.setFormat(match.start(), match.end() - match.start(),
                          self.label_format)
        
        # Highlight function definitions
        import re
        function_pattern = r'@\w+'
        for match in re.finditer(function_pattern, text):
            self.setFormat(match.start(), match.end() - match.start(),
                          self.function_format)

def PLUGIN_ENTRY():
    return IDA2LLVMPlugin()

class IDA2LLVMPlugin(ida_idaapi.plugin_t):

    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_HIDE
    comment = "Microcode Lifter to LLVM"
    help = ""
    wanted_name = "IDA2LLVM"
    wanted_hotkey = ""

    def init(self):
        
        action = {
            'id': 'ida2llvm:view_lifting',
            'name': 'Lifting Viewer',
            'hotkey': 'Ctrl-Alt-L',
            'comment': 'UI for which function to lift',
            'menu_location': 'Edit/IDA2LLVM/Viewer'
        }
        if not ida_kernwin.register_action(ida_kernwin.action_desc_t(
            action['id'],
            action['name'], # The name the user sees
            IDA2LLVMController(), # The function to call
            action['hotkey'], # A shortcut, if any (optional)
            action['comment'], # A comment, if any (optional)
            -1
        )):
            print("ida2llvm: failed to register action")

        if not ida_kernwin.attach_action_to_menu(
            action['menu_location'], # The menu location
            action['id'], # The unique function ID
            0):
            print("ida2llvm: failed to attach to menu")

        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        ida_kernwin.warning("%s cannot be run as a script in IDA." % self.wanted_name)

    def term(self):
        pass

class IDA2LLVMController(ida_kernwin.action_handler_t):
    """
    The control component of BinaryLift Explorer.
    """
    def __init__(self):
        from llvmlite import ir
        ida_kernwin.action_handler_t.__init__(self)
        self.current_address = None
        self.cache = dict()
        self.namecache = dict()  # address -> mangled name
        self.config = dict()
        self.m = ir.Module()

        class AddressHook(ida_kernwin.UI_Hooks):
            def __init__(self, controller):
                ida_kernwin.UI_Hooks.__init__(self)
                self.controller = controller
            def database_inited(self, is_new_database, idc_script):
                self.controller.cache = dict()
                self.controller.namecache = dict()  # address -> mangled name
                self.controller.config = dict()
                self.controller.m = ir.Module()
            def screen_ea_changed(self, ea, prev_ea):
                self.controller.screen_ea = ea
                self.controller.view.refresh()
        
        self._hook = AddressHook(self)
        self._hook.hook()
        self.view = IDA2LLVMView(self)

    def activate(self, ctx):
        self.view.Show()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

    def isScreenEaInvalid(self):
        return ida_funcs.get_func(self.screen_ea) is None

    def resolveName(self, current_address):
        func_name = ida_name.get_name(current_address)
        if func_name != self.namecache.get(current_address, None):
            print("NAME NOT SYNCED, PROBABLY CHANGED")
        self.namecache[current_address] = func_name
        return self.namecache[current_address]

    def declareCurrentFunction(self, isDeclare):
        current_name = self.resolveName(self.current_address)
        self.config[self.current_address] = bool(isDeclare)
        self.cache[self.current_address] = self.getLiftedText()
        self.view.refresh()

    def updateFunctionSelected(self, selectName):
        if selectName == "":
            return
        current_address, _ = selectName.split(":", maxsplit=1)
        self.current_address = int(current_address, 16)
        current_name = self.resolveName(self.current_address)
        ida_kernwin.jumpto(self.current_address)
        ida_kernwin.activate_widget(self.view._twidget, True)

    def insertAllFunctions(self):
        for f_ea in idautils.Functions():
            name = ida_funcs.get_func_name(f_ea)
            if (ida_funcs.get_func(f_ea).flags & ida_funcs.FUNC_LIB
                or ida_segment.segtype(f_ea) & ida_segment.SEG_XTRN
                or name.startswith("_")):
                continue
            self.insertFunctionAtEa(f_ea)

    def insertFunctionAtScreenEa(self):
        if self.isScreenEaInvalid():
            return
        self.current_address = ida_funcs.get_func(self.screen_ea).start_ea
        self.insertFunctionAtEa(self.current_address)
        self.view.refresh()

    def insertFunctionAtEa(self, ea):
        temp_ea = self.current_address
        self.current_address = ea
        current_name = self.resolveName(self.current_address)

        if self.current_address not in self.config:
            self.config[self.current_address] = False
            
        self.cache[self.current_address] = self.getLiftedText()
        self.current_address = temp_ea

    def removeFromModule(self, func_name):
        from contextlib import suppress
        from llvmlite import ir
        
        # func_name is the mangled name from IDA
        with suppress(KeyError):
            old_func = self.m.globals[func_name]
            _m = ir.Module()
            for name, gv in self.m.globals.items():
                if name != func_name:
                    gv.parent = _m
                    _m.add_global(gv)
            self.m = _m

    def getLiftedText(self):
        import ida2llvm

        func_name = self.resolveName(self.current_address)
        isDeclare = self.config[self.current_address]
        self.removeFromModule(func_name)
        llvm_f = ida2llvm.function.lift_function(self.m, func_name, isDeclare)

        for f in self.m.functions:
            f_name = f.name  # This is the mangled name from IDA
            f_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, f_name)
            self.namecache[f_ea] = f_name
            self.config[f_ea] = f.is_declaration
            self.cache[f_ea] = str(f)

            # Demangle name for display only
            demangled_name, _ = ida2llvm._utils.demangle_name(f_name)
            display_name = f"{hex(f_ea)}: {demangled_name}"
            if not self.view.function_list.findItems(display_name, QtCore.Qt.MatchFlag.MatchExactly):
                self.view.function_list.addItem(display_name)

        return str(llvm_f)

    def save_to_file(self):
       filename, _ = QtWidgets.QFileDialog.getSaveFileName(None, 'Save Lifted LLVM IR', '', 'LLVM IR (*.ll)')
       if filename:
           with open(filename, 'w') as f:
               f.write(str(self.m))

class IDA2LLVMView(ida_kernwin.PluginForm):
    """
    The view component of BinaryLift Explorer.
    """
    def __init__(self, controller):
        ida_kernwin.PluginForm.__init__(self)
        self.controller = controller
        self.created = False

    def Show(self):
        return ida_kernwin.PluginForm.Show(
            self, "IDA2LLVM Viewer",
            options=(ida_kernwin.PluginForm.WOPN_PERSIST |
                     ida_kernwin.PluginForm.WCLS_SAVE |
                     ida_kernwin.PluginForm.WOPN_MENU |
                     ida_kernwin.PluginForm.WOPN_RESTORE |
                     ida_kernwin.PluginForm.WOPN_TAB))

    def refresh(self):
        if not self.created:
            return
        self.lifting_settings.setDisabled(self.function_list.currentRow() == -1)
        self.curr_ea_button.setDisabled(self.controller.isScreenEaInvalid())
        if not self.controller.isScreenEaInvalid():
            self.curr_ea_button.setText(f"{'Redefine' if ida_funcs.get_func(self.controller.screen_ea).start_ea in self.controller.config else 'Add'} function at current address ({hex(self.controller.screen_ea)})")
        if self.controller.current_address:
            self.isDeclare.setChecked(self.controller.config[self.controller.current_address])
            self.code_view.setText(self.controller.cache[self.controller.current_address])

    def create_code_view(self):
        self.code_view = QtWidgets.QTextEdit(self.widget)
        # Enable line wrapping and read-only mode
        self.code_view.setLineWrapMode(QtWidgets.QTextEdit.LineWrapMode.NoWrap)
        self.code_view.setReadOnly(True)
        # Set monospace font
        font = QFont("Courier New", 10)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.code_view.setFont(font)
        # Add syntax highlighter
        self.highlighter = LLVMSyntaxHighlighter(self.code_view.document())

    def create_function_settings(self):
        self.isDeclare = QtWidgets.QCheckBox("Keep function as declare-only")
        self.isDeclare.setChecked(False)
        self.isDeclare.stateChanged.connect(self.controller.declareCurrentFunction)
        
        self.lifting_settings = QtWidgets.QGroupBox("Lift Settings")
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.isDeclare)
        self.lifting_settings.setLayout(layout)

    def create_function_list(self):
        controller = self.controller
        
        # Create search box for filtering
        self.search_box = QtWidgets.QLineEdit(self.widget)
        self.search_box.setPlaceholderText("Search functions...")
        self.search_box.textChanged.connect(self.filter_function_list)
        
        class FunctionListWidget(QtWidgets.QListWidget):
            def __init__(self, parent, *args, **kwargs):
                super().__init__(parent, *args, **kwargs)
                import ida2llvm

                for address in controller.config:
                    mangled_name = controller.resolveName(address)
                    demangled_name, _ = ida2llvm._utils.demangle_name(mangled_name)
                    is_declare = controller.config[address]
                    item = QtWidgets.QListWidgetItem(f"{hex(address)}: {demangled_name}")
                    # Add icon to indicate declare vs defined
                    if is_declare:
                        item.setForeground(QColor(150, 150, 150))  # Gray for declarations
                        item.setToolTip("Declaration only")
                    else:
                        item.setForeground(QColor(0, 128, 0))  # Green for definitions
                        item.setToolTip("Fully defined")
                    self.addItem(item)
                    
            def keyPressEvent(self, event):
                if event.key() == QtCore.Qt.Key.Key_Delete:
                    row = self.currentRow()
                    item = self.takeItem(row)
                    address, demangled_name = item.text().split(": ", maxsplit=1)
                    address = int(address, 16)
                    # Get the mangled name from our cache to remove from module
                    mangled_name = controller.namecache[address]
                    controller.removeFromModule(mangled_name)
                    del controller.cache[address]
                    del controller.namecache[address]
                    del controller.config[address]
                    del item
                else:
                    super().keyPressEvent(event)
        self.function_list = FunctionListWidget(self.widget)
        self.function_list.setSortingEnabled(True)
        self.function_list.currentTextChanged.connect(self.controller.updateFunctionSelected)
        
    def filter_function_list(self, text):
        """Filter function list based on search text."""
        for i in range(self.function_list.count()):
            item = self.function_list.item(i)
            if text.lower() in item.text().lower():
                item.setHidden(False)
            else:
                item.setHidden(True)

    def OnCreate(self, form):
        self._twidget = self.GetWidget()
        self.widget = self.FormToPyQtWidget(form)
        layout = QtWidgets.QGridLayout(self.widget)

        self.curr_ea_button         = QtWidgets.QPushButton("Add function at current address", self.widget)
        self.all_functions_button   = QtWidgets.QPushButton("Add all IDA-defined functions", self.widget)
        self.lift_button            = QtWidgets.QPushButton("Lift and save to file", self.widget)
        
        # Add progress bar
        self.progress_bar = QtWidgets.QProgressBar(self.widget)
        self.progress_bar.setVisible(False)

        self.curr_ea_button.clicked.connect(self.controller.insertFunctionAtScreenEa)
        self.all_functions_button.clicked.connect(self.controller.insertAllFunctions)
        self.lift_button.clicked.connect(self.controller.save_to_file)

        self.create_code_view()
        self.create_function_settings()
        self.create_function_list()

        # arrange the widgets in a 'grid'         row  col  row span  col span
        layout.addWidget(self.code_view,            0,   0,        5,        1)
        layout.addWidget(self.search_box,           0,   1,        1,        1)
        layout.addWidget(self.function_list,        1,   1,        1,        1)
        layout.addWidget(self.lifting_settings,     2,   1,        1,        1)
        layout.addWidget(self.curr_ea_button,       3,   1,        1,        1)
        layout.addWidget(self.all_functions_button, 4,   1,        1,        1)
        layout.addWidget(self.progress_bar,         5,   1,        1,        1)
        layout.addWidget(self.lift_button,          6,   1,        1,        1)

        self.widget.setLayout(layout)
        self.created = True
        self.refresh()