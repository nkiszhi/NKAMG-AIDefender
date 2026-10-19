"""Install only runtime guards into an existing v8 image; keep its model code."""
import argparse
import ast
from pathlib import Path


def patch_source(source, fragment):
    tree = ast.parse(source)
    nodes = {node.name: node for node in tree.body
             if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    required = {'predict_single', 'predict_directory', '_load_ensemble',
                '_infer_expected_view_dims', '_scan_single_pe', 'readyz'}
    missing = required - nodes.keys()
    if missing:
        raise ValueError(f'Incompatible image: missing functions {sorted(missing)}')
    if '_warm_runtime_models' in nodes:
        raise ValueError('Runtime patch already installed; use the original v8 base image')
    # Replace exactly two routes, keeping all feature extraction and response
    # formatting intact. Abort rather than blindly copying a newer engine file.
    lines = source.splitlines(keepends=True)
    single = nodes['predict_single']
    batch = nodes['predict_directory']
    replacements = []
    start = min([single.lineno] + [d.lineno for d in single.decorator_list]) - 1
    replacements.append((start, single.end_lineno, ''))
    start = min([batch.lineno] + [d.lineno for d in batch.decorator_list]) - 1
    original = ''.join(lines[batch.lineno - 1:batch.end_lineno])
    original = original.replace('async def predict_directory(', 'async def _predict_directory_unprotected(', 1)
    replacements.append((start, batch.end_lineno, original + '\n'))
    for start, end, replacement in sorted(replacements, reverse=True):
        lines[start:end] = [replacement]
    result = ''.join(lines) + '\n\n' + fragment
    compile(result, 'engine/app.py', 'exec')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--app', default='/app/engine/app.py')
    parser.add_argument('--fragment', default='/tmp/runtime_endpoints.py')
    args = parser.parse_args()
    app_path = Path(args.app)
    result = patch_source(app_path.read_text(encoding='utf-8'), Path(args.fragment).read_text(encoding='utf-8'))
    app_path.write_text(result, encoding='utf-8')
    print('Installed bounded inference runtime into', app_path)
