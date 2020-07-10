pipeline {
  agent any
  stages {
    stage('Checkout from GitHub') {
      steps {
        git(url: 'https://github.com/ayushpriya10/aws-security-hub-scan-with-trivy.git', branch: 'master')
      }
    }

    stage('Auth to ECR') {
      steps {
        sh '$(aws ecr get-login --no-include-email --region us-east-1)'
      }
    }

    stage('Docker build') {
      environment {
        docker_image = 'vulnerable_image'
        docker_tag = 'latest'
        ecr_repo = '024697031416.dkr.ecr.us-east-1.amazonaws.com/intentionally-vulnerable-image:latest'
      }
      steps {
        sh 'docker build -t $docker_image:$docker_tag .'
      }
    }

    stage('Trivy Scan') {
      steps {
        sh '''trivy -f json -o results.json --exit-code 0 --severity HIGH,MEDIUM,LOW --quiet --auto-refresh $docker_image:$docker_tag
trivy -f json -o results.json --exit-code 1 --severity CRITICAL --quiet --auto-refresh $docker_image:$docker_tag'''
      }
    }

    stage('Docker Tag and Push') {
      steps {
        sh '''docker tag $docker_image:$docker_tag $ecr_repo
docker push $ecr_repo'''
      }
    }

    stage('Add Findings to Security Hub') {
      steps {
        sh '''echo trivy scan completed on `date`
python3 sechub_parser.py
echo Report Sent to Security Hub on `date`'''
      }
    }

  }
  environment {
    docker_image = 'vulnerable_image'
    docker_tag = 'latest'
    ecr_repo = '024697031416.dkr.ecr.us-east-1.amazonaws.com/intentionally-vulnerable-image:latest'
    AWS_DEFAULT_REGION = 'us-east-1'
  }
}