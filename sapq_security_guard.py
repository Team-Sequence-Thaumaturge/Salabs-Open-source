import re
import os

class SAPQSecurityGuard:
    """
    Phase 25.0: AST Taint & Security Smell Scanner
    Language-Agnostic AST Taint Engine.
    """
    def __init__(self, target_filepath, ast_parser=None):
        self.filepath = target_filepath
        self.filename = os.path.basename(target_filepath)
        self.ast_parser = ast_parser
        self.issues = []
        self.unsanitized_flows = 0
        self.hardcoded_credentials = 0
        self.other_smells = 0

        # Universal Semantic Matrix Definitions
        self.sources = {'location.search', 'location.hash', 'window.name', 'input.value', 'postMessage', 'sys.argv', 'os.environ', 'sys.argv[1]', 'params.get'}
        self.sinks = {'innerHTML', 'outerHTML', 'eval', 'exec', 'document.write', 'setTimeout', 'setInterval', 'os.system', 'subprocess.call', 'subprocess.Popen'}
        self.sanitizers = {'escapeHTML', 'encodeURIComponent', 'parseInt', 'Number', 'int', 'float', 'html.escape', 'urllib.parse.quote'}

        self.credential_keywords = re.compile(r'(api_key|secret|token|password|auth|pwd)', re.IGNORECASE)
        self.plaintext_protocols = re.compile(r'(http://|ws://|ftp://)', re.IGNORECASE)
        # Basic catastrophic backtracking pattern detection (nested quantifiers like (a+)+, (a|a)+, .*.*)
        self.unsafe_regex = re.compile(r'(\([^)]*\+[^)]*\)\+|\([^)]*\*[^)]*\)\*|(\.[\*\+]){2,})')

    def analyze(self):
        if not self.ast_parser or not self.ast_parser.ast:
            return self._generate_report()

        if self.ast_parser.language == 'python':
            self._analyze_python()
        else:
            self._analyze_js()

        return self._generate_report()

    def _add_issue(self, issue_type, line, details):
        self.issues.append({
            "type": issue_type,
            "line": line,
            "details": details
        })
        if issue_type == "UNSANITIZED_DATA_FLOW":
            self.unsanitized_flows += 1
        elif issue_type == "HARDCODED_CREDENTIAL":
            self.hardcoded_credentials += 1
        elif issue_type in ["UNSAFE_REGEX", "PLAINTEXT_PROTOCOL"]:
            self.other_smells += 1

    def _analyze_js(self):
        # Intra-procedural taint tracking
        tainted_vars = {} # map var name to { 'line': line, 'source': source }

        def visitor(node):
            if not hasattr(node, 'type'): return
            line = getattr(node.loc.start, 'line', 0) if getattr(node, 'loc', None) else 0

            # Smell: Unsafe Regex (Literal)
            if node.type == 'Literal' and hasattr(node, 'regex'):
                pattern = getattr(node.regex, 'pattern', '')
                if self.unsafe_regex.search(pattern):
                    self._add_issue("UNSAFE_REGEX", line, f"Potential ReDoS vulnerability in regex: {pattern}")

            # Smell: Unsafe Regex (New RegExp)
            if node.type == 'NewExpression' and getattr(node.callee, 'name', '') == 'RegExp':
                if node.arguments and node.arguments[0].type == 'Literal':
                    pattern = str(node.arguments[0].value)
                    if self.unsafe_regex.search(pattern):
                        self._add_issue("UNSAFE_REGEX", line, f"Potential ReDoS vulnerability in RegExp: {pattern}")

            # Smell: Plaintext Protocol & Hardcoded Credential
            if node.type == 'Literal' and isinstance(node.value, str):
                val = node.value
                if self.plaintext_protocols.search(val):
                    self._add_issue("PLAINTEXT_PROTOCOL", line, f"Plaintext protocol found: {val}")

                # Check for Hardcoded Credentials via Assignment or VariableDeclarator
                # Note: We rely on the parent context, but esprima doesn't have parent links.
                # So we check VariableDeclarator and AssignmentExpression instead.

            if node.type == 'VariableDeclarator' and node.id.type == 'Identifier' and node.init and node.init.type == 'Literal' and isinstance(node.init.value, str):
                if self.credential_keywords.search(node.id.name) and len(node.init.value) > 0:
                    self._add_issue("HARDCODED_CREDENTIAL", line, f"Hardcoded credential assigned to '{node.id.name}'")

            if node.type == 'AssignmentExpression' and node.left.type == 'Identifier' and node.right.type == 'Literal' and isinstance(node.right.value, str):
                if self.credential_keywords.search(node.left.name) and len(node.right.value) > 0:
                    self._add_issue("HARDCODED_CREDENTIAL", line, f"Hardcoded credential assigned to '{node.left.name}'")

            # Taint Tracking (Intra-procedural)
            # 1. Source -> Variable
            if node.type == 'VariableDeclarator' and node.id.type == 'Identifier' and node.init:
                source_name = self._get_source_name(node.init)
                if source_name in self.sources:
                    tainted_vars[node.id.name] = {'line': line, 'source': source_name}
                elif node.init.type == 'Identifier' and node.init.name in tainted_vars:
                    tainted_vars[node.id.name] = tainted_vars[node.init.name] # Propagate taint
                elif node.init.type == 'CallExpression':
                    # Check for params.get() or similar
                    call_source = self._get_source_name(node.init.callee)
                    if call_source in self.sources:
                        tainted_vars[node.id.name] = {'line': line, 'source': call_source}

            if node.type == 'AssignmentExpression' and node.left.type == 'Identifier':
                source_name = self._get_source_name(node.right)
                if source_name in self.sources:
                    tainted_vars[node.left.name] = {'line': line, 'source': source_name}
                elif node.right.type == 'Identifier' and node.right.name in tainted_vars:
                    tainted_vars[node.left.name] = tainted_vars[node.right.name]

            # 2. Sanitization (Removes taint)
            if node.type == 'AssignmentExpression' and node.left.type == 'Identifier':
                if self._is_sanitized(node.right):
                    if node.left.name in tainted_vars:
                        del tainted_vars[node.left.name]

            # 3. Variable -> Sink
            if node.type == 'AssignmentExpression' and node.left.type == 'MemberExpression':
                sink_name = getattr(node.left.property, 'name', '')
                if sink_name in self.sinks:
                    if node.right.type == 'Identifier' and node.right.name in tainted_vars:
                        self._add_issue("UNSANITIZED_DATA_FLOW", line, f"Tainted data from '{tainted_vars[node.right.name]['source']}' flows into sink '{sink_name}' via variable '{node.right.name}'")
                    elif self._get_source_name(node.right) in self.sources:
                        self._add_issue("UNSANITIZED_DATA_FLOW", line, f"Direct tainted data flow from '{self._get_source_name(node.right)}' into sink '{sink_name}'")

            if node.type == 'CallExpression':
                sink_name = self._get_sink_name_from_callee(node.callee)
                if sink_name in self.sinks:
                    for arg in node.arguments:
                        if arg.type == 'Identifier' and arg.name in tainted_vars:
                            self._add_issue("UNSANITIZED_DATA_FLOW", line, f"Tainted data from '{tainted_vars[arg.name]['source']}' flows into sink '{sink_name}' via variable '{arg.name}'")
                        elif self._get_source_name(arg) in self.sources:
                            self._add_issue("UNSANITIZED_DATA_FLOW", line, f"Direct tainted data flow from '{self._get_source_name(arg)}' into sink '{sink_name}'")

        self.ast_parser._traverse(self.ast_parser.ast, visitor)

    def _analyze_python(self):
        import ast as pyast
        tainted_vars = {}

        class SecurityVisitor(pyast.NodeVisitor):
            def __init__(self, guard):
                self.guard = guard

            def visit_Assign(self, node):
                line = getattr(node, 'lineno', 0)
                # Check for Hardcoded Credentials
                if isinstance(node.value, pyast.Constant) and isinstance(node.value.value, str):
                    val = node.value.value
                    if self.guard.plaintext_protocols.search(val):
                        self.guard._add_issue("PLAINTEXT_PROTOCOL", line, f"Plaintext protocol found: {val}")

                    for target in node.targets:
                        if isinstance(target, pyast.Name) and self.guard.credential_keywords.search(target.id) and len(val) > 0:
                            self.guard._add_issue("HARDCODED_CREDENTIAL", line, f"Hardcoded credential assigned to '{target.id}'")

                # Taint tracking
                for target in node.targets:
                    if isinstance(target, pyast.Name):
                        source_name = self.guard._get_py_source_name(node.value)
                        if source_name in self.guard.sources:
                            tainted_vars[target.id] = {'line': line, 'source': source_name}
                        elif isinstance(node.value, pyast.Name) and node.value.id in tainted_vars:
                            tainted_vars[target.id] = tainted_vars[node.value.id]

                        # Sanitization
                        if self.guard._is_py_sanitized(node.value):
                            if target.id in tainted_vars:
                                del tainted_vars[target.id]

                self.generic_visit(node)

            def visit_Call(self, node):
                line = getattr(node, 'lineno', 0)
                sink_name = self.guard._get_py_sink_name(node.func)

                # Check regex compilation
                if sink_name == 're.compile':
                    if node.args and isinstance(node.args[0], pyast.Constant) and isinstance(node.args[0].value, str):
                        pattern = node.args[0].value
                        if self.guard.unsafe_regex.search(pattern):
                            self.guard._add_issue("UNSAFE_REGEX", line, f"Potential ReDoS vulnerability in regex: {pattern}")

                # Sink check
                if sink_name in self.guard.sinks or sink_name.split('.')[-1] in self.guard.sinks:
                    for arg in node.args:
                        if isinstance(arg, pyast.Name) and arg.id in tainted_vars:
                            self.guard._add_issue("UNSANITIZED_DATA_FLOW", line, f"Tainted data from '{tainted_vars[arg.id]['source']}' flows into sink '{sink_name}' via variable '{arg.id}'")
                        elif self.guard._get_py_source_name(arg) in self.guard.sources:
                            self.guard._add_issue("UNSANITIZED_DATA_FLOW", line, f"Direct tainted data flow from '{self.guard._get_py_source_name(arg)}' into sink '{sink_name}'")

                self.generic_visit(node)

        SecurityVisitor(self).visit(self.ast_parser.ast)

    def _get_source_name(self, node):
        if not node: return ""
        if node.type == 'MemberExpression':
            obj_name = getattr(node.object, 'name', '')
            prop_name = getattr(node.property, 'name', '')
            return f"{obj_name}.{prop_name}"
        return ""

    def _is_sanitized(self, node):
        if not node: return False
        if node.type == 'CallExpression':
            callee_name = getattr(node.callee, 'name', '')
            if callee_name in self.sanitizers:
                return True
        return False

    def _get_sink_name_from_callee(self, callee):
        if not callee: return ""
        if callee.type == 'Identifier':
            return callee.name
        if callee.type == 'MemberExpression':
            return getattr(callee.property, 'name', '')
        return ""

    def _get_py_source_name(self, node):
        import ast as pyast
        if isinstance(node, pyast.Attribute):
            if isinstance(node.value, pyast.Name):
                return f"{node.value.id}.{node.attr}"
        elif isinstance(node, pyast.Subscript):
            if isinstance(node.value, pyast.Attribute):
                if isinstance(node.value.value, pyast.Name):
                    return f"{node.value.value.id}.{node.value.attr}"
        return ""

    def _is_py_sanitized(self, node):
        import ast as pyast
        if isinstance(node, pyast.Call):
            name = self._get_py_sink_name(node.func)
            if name in self.sanitizers or name.split('.')[-1] in self.sanitizers:
                return True
        return False

    def _get_py_sink_name(self, node):
        import ast as pyast
        if isinstance(node, pyast.Name):
            return node.id
        elif isinstance(node, pyast.Attribute):
            if isinstance(node.value, pyast.Name):
                return f"{node.value.id}.{node.attr}"
            return node.attr
        return ""

    def _generate_report(self):
        score = 100 - (self.unsanitized_flows * 15) - (self.hardcoded_credentials * 10) - (self.other_smells * 5)
        score = max(0, score)

        return {
            "security_health_score": score,
            "issues": self.issues,
            "metrics": {
                "UNSANITIZED_DATA_FLOW": self.unsanitized_flows,
                "HARDCODED_CREDENTIAL": self.hardcoded_credentials,
                "OTHER_SMELLS": self.other_smells
            }
        }
