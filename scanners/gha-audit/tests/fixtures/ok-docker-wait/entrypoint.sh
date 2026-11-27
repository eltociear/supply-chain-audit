#!/bin/bash
until </dev/tcp/localhost/5432; do sleep 1; done
echo "db up"
