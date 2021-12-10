```
docker run \
    --rm -it \
    -v ${PWD}/config.yml:/home/aws-nuke/config.yml \
    -v /home/${USER}/.aws:/home/aws-nuke/.aws \
    quay.io/rebuy/aws-nuke:v2.11.0 \
    --access-key-id= \
    --secret-access-key= \
    --config /home/aws-nuke/config.yml

```