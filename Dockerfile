# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

FROM composer:1.7.2

RUN git clone https://github.com/aquasecurity/trivy-ci-test.git && cd trivy-ci-test && rm Cargo.lock && rm Pipfile.lock

CMD apk add --no-cache mysql-client
ENTRYPOINT ["mysql"]
