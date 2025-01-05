echo DATABASE_URL=postgres://postgres:n]jcH(F5@//cloudsql/local-tracker-441721-v0:REGION: fana-dashboard-db
/DATABASE_NAME > .env
echo SECRET_KEY=$(cat /dev/urandom | LC_ALL=C tr -dc '[:alpha:]'| fold -w 50 | head -n1) >> .env
echo "Completed the setup"/dev/urandom


gcloud secrets add-iam-policy-binding django_settings --member serviceAccount:local-tracker-441721-v0@appspot.gserviceaccount.com --role roles/secretmanager.secretAccessor
gcloud iam service-accounts list

gcloud secrets add-iam-policy-binding django_settings --member serviceAccount:jayant-anand-fana@local-tracker-441721-v0.iam.gserviceaccount.com --role roles/secretmanager.secretAccessor
gcloud iam service-accounts create appspot --display-name "App Engine default service account"
gcloud secrets add-iam-policy-binding django_settings --member serviceAccount:appspot@local-tracker-441721-v0.iam.gserviceaccount.com --role roles/secretmanager.secretAccessor


--------------------

cloud-sql-proxy.exe local-tracker-441721-v0:asia-south2-c:fana-dashboard-db


---- Create DATABASE_NAME ----

gcloud sql instances create fana-dashboard-db   --region asia-south2  --tier db-f1-micro --database-version POSTGRES_14
