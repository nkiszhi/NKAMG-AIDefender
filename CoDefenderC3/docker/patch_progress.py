"""Upgrade original or guarded v8 engine code without replacing its model definitions."""
import ast
from pathlib import Path


def upgrade_source(source, fragment):
    tree = ast.parse(source)
    functions = {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    if '_scan_single_pe' not in functions or '_predict_per_model' not in functions:
        raise ValueError('Incompatible v8 engine')
    # Upgrades are idempotent: remove earlier endpoint fragment, then add ours.
    marker = '# This fragment is installed into engine/app.py by patch_runtime.py.'
    if marker in source:
        source = source[:source.index(marker)]
    tree = ast.parse(source)

    class Upgrade(ast.NodeTransformer):
        def visit_FunctionDef(self, node):
            name = node.name
            self.generic_visit(node)
            options = {
                '_predict_malgraph_single': ['sample'],
                '_extract_views_for_single_sample': ['extracted_features'],
                '_predict_per_model': ['selected_models', 'malgraph_sample', 'on_result'],
                '_scan_single_pe': ['per_model_override'],
            }.get(name, [])
            present = {argument.arg for argument in node.args.args}
            for option in options:
                if option not in present:
                    node.args.args.append(ast.arg(arg=option))
                    node.args.defaults.append(ast.Constant(None))
            if name == '_predict_malgraph_single':
                imports = [statement for statement in node.body if isinstance(statement, ast.ImportFrom) and statement.module == 'models.MalGraph_2022.utils']
                node.body = [statement for statement in node.body if statement not in imports]
                for index, statement in enumerate(node.body):
                    if isinstance(statement, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'sample' for target in statement.targets):
                        if isinstance(statement.value, ast.Call) and getattr(statement.value.func, 'id', '') == 'extract_cfg_and_fcg':
                            node.body[index] = ast.If(ast.Compare(ast.Name('sample', ast.Load()), [ast.Is()], [ast.Constant(None)]), imports + [statement], [])
            if name == '_extract_views_for_single_sample':
                class Features(ast.NodeTransformer):
                    def visit_Call(self, call):
                        self.generic_visit(call)
                        if isinstance(call.func, ast.Attribute) and call.func.attr == 'extract_fast':
                            return ast.IfExp(ast.Compare(ast.Name('extracted_features', ast.Load()), [ast.Is()], [ast.Constant(None)]), call, ast.Name('extracted_features', ast.Load()))
                        return call

                    def visit_If(self, statement):
                        self.generic_visit(statement)
                        if isinstance(statement.test, ast.Name) and statement.test.id == 'include_de':
                            statement.test = ast.parse('include_de and extracted_features is None', mode='eval').body
                        return statement

                    def visit_UnaryOp(self, expression):
                        self.generic_visit(expression)
                        if isinstance(expression.op, ast.Not) and isinstance(expression.operand, ast.Name) and expression.operand.id == 'include_de':
                            return ast.parse('(not include_de) or extracted_features is not None', mode='eval').body
                        return expression
                if 'extracted_features' not in present:
                    node = Features().visit(node)
            if name == '_predict_per_model' and 'selected_models' not in present:
                class Models(ast.NodeTransformer):
                    def visit_For(self, loop):
                        self.generic_visit(loop)
                        if isinstance(loop.target, ast.Name) and loop.target.id == 'mname':
                            loop.body.insert(0, ast.parse('if selected_models is not None and mname not in selected_models: continue').body[0])
                        return loop

                    def visit_Call(self, call):
                        self.generic_visit(call)
                        if getattr(call.func, 'id', '') == '_predict_malgraph_single':
                            call.keywords.append(ast.keyword('sample', ast.Name('malgraph_sample', ast.Load())))
                        return call

                    def visit_Expr(self, expression):
                        call = expression.value
                        if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == 'append' and getattr(call.func.value, 'id', '') == 'results':
                            return [expression, ast.parse('if on_result: on_result(dict(item))').body[0]]
                        return self.generic_visit(expression)
                node = Models().visit(node)
            if name == '_scan_single_pe' and 'per_model_override' not in present:
                positions = [i for i, statement in enumerate(node.body) if isinstance(statement, ast.Assign) and
                             any(isinstance(target, ast.Name) and target.id == 'per_model' for target in statement.targets)]
                if len(positions) != 1:
                    raise ValueError('Unexpected single-scan model block')
                end = positions[0]
                if end < 1 or not isinstance(node.body[end-1], ast.Assign):
                    raise ValueError('Unexpected single-scan feature block')
                node.body[end-1:end+1] = [ast.If(
                    ast.parse('per_model_override is None', mode='eval').body,
                    node.body[end-1:end+1], ast.parse('per_model = per_model_override').body)]
            if name == 'predict_single':
                return None
            return node

        def visit_AsyncFunctionDef(self, node):
            if node.name in ('predict_single', 'predict_stream', '_warm_runtime_models', '_run_guarded', 'predict_directory'):
                if node.name == 'predict_directory':
                    node.name = '_predict_directory_unprotected'
                    node.decorator_list = []
                    return node
                return None
            return node

    tree = Upgrade().visit(tree)
    ast.fix_missing_locations(tree)
    result = ast.unparse(tree) + '\n\n' + fragment
    compile(result, 'engine/app.py', 'exec')
    return result


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--app', default='/app/engine/app.py')
    parser.add_argument('--fragment', default='/tmp/runtime_endpoints.py')
    arguments = parser.parse_args()
    path = Path(arguments.app)
    path.write_text(upgrade_source(path.read_text(encoding='utf-8'),
                                  Path(arguments.fragment).read_text(encoding='utf-8')), encoding='utf-8')
    print('Installed staged progress and isolated analysis runtime')
