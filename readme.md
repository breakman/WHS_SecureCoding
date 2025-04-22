# Secure Coding 과제

## Tiny Secondhand Shopping Platform 시큐어 코딩 보완 과제


## requirements

anaconda 혹은 miniconda 를 설치해야 합니다.
- https://docs.anaconda.com/free/miniconda/index.html

```
git clone https://github.com/ugonfor/secure-coding
conda env create -f enviroments.yaml
```

## usage

다음 명령을 통해 서버를 실행합니다.

```
python app.py
```
만약에 외부 
if you want to test on external machine, you can utilize the ngrok to forwarding the url.
```
# optional
sudo snap install ngrok
ngrok http 5000
```