gcloud sql instances create fana-dashboard-db-xyz --project local-tracker-441721-v0 --database-version POSTGRES_10 --tier db-n1-standard-2 --region asia-east1



gcloud sql databases create DATABASE_NAME \
    --instance INSTANCE_NAME



gcloud services enable appengine.googleapis.com     cloudbuild.googleapis.com sqladmin.googleapis.com secretmanager.googleapis.com


gcloud sql users set-password postgres --host=% --instance fana-dashboard-db --password fana1234
