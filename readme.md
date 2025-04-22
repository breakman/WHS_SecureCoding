# Secure Coding 과제

## Tiny Secondhand Shopping Platform 시큐어 코딩 보완 과제
시큐어 코딩 - 요구사항 기능 추가 및 보안 약점 보안 과제 입니다.

## requirements

anaconda 혹은 miniconda 를 설치해야 합니다.
- https://docs.anaconda.com/free/miniconda/index.html

```
git clone https://github.com/breakman/WHS_SecureCoding.git
conda env create -f enviroments.yaml
```

## usage

다음 명령을 통해 서버를 실행합니다.

```
python app.py
```
만약에 외부에서 테스트 하고 싶으면 ngrok을 이용해서 URL을 포워딩할 수 있습니다.
```
# optional
sudo snap install ngrok
ngrok http 5000
```