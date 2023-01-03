To recreate the test files:
- Start a miniconda container:
```bash
docker run --name miniconda --rm -it continuumio/miniconda3@sha256:58b1c7df8d69655ffec017ede784a075e3c2e9feff0fc50ef65300fc75aa45ae bash
```
- In the container, initialize a conda environment:
```bash
conda create --yes -n test-dep-parser python=3.9.12
```
- Export conda package definitions out of the container:
```bash
docker cp miniconda:/opt/conda/envs/test-dep-parser/conda-meta/_libgcc_mutex-0.1-main.json .
docker cp miniconda:/opt/conda/envs/test-dep-parser/conda-meta/libgomp-11.2.0-h1234567_1.json .
```
