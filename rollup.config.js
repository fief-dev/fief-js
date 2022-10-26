import commonjs from '@rollup/plugin-commonjs';
import json from '@rollup/plugin-json';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import typescript from '@rollup/plugin-typescript';
import { terser } from 'rollup-plugin-terser';

export default [
  // browser-friendly UMD build
  {
    input: 'src/index.ts',
    output: {
      name: 'fief',
      file: 'build/index.umd.js',
      format: 'umd',
      sourcemap: true,
    },
    plugins: [
      {
        name: 'Fake node-fetch in browser build',
        resolveId: (source, _importer, _options) => {
          if (source === 'node-fetch') {
            return './src/fetch/node-fetch-fake.ts';
          }
          return null;
        },
      },
      nodeResolve({
        jsnext: true,
        preferBuiltins: true,
        browser: true,
      }),
      json(),
      commonjs(),
      typescript(),
      terser(),
    ],
  },
  // CommonJS (for Node)
  {
    input: [
      'src/index.ts',
      'src/react/index.ts',
      'src/express/index.ts',
      'src/nextjs/index.ts',
    ],
    plugins: [
      typescript({
        declaration: false,
        rootDir: 'src',
        exclude: ['**/*.test.ts'],
      }),
    ],
    output: [
      {
        dir: 'build/cjs',
        format: 'cjs',
        sourcemap: true,
        preserveModules: true,
        preserveModulesRoot: 'src',
      },
    ],
  },
  // ES module (for bundlers) build.
  {
    input: [
      'src/index.ts',
      'src/react/index.ts',
      'src/express/index.ts',
      'src/nextjs/index.ts',
    ],
    plugins: [
      typescript({
        declaration: true,
        declarationDir: 'build/esm',
        rootDir: 'src',
        exclude: ['**/*.test.ts'],
      }),
    ],
    output: [
      {
        dir: 'build/esm',
        format: 'es',
        sourcemap: true,
        preserveModules: true,
        preserveModulesRoot: 'src',
      },
    ],
  },
];
