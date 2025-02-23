# Generated by Django 5.0.7 on 2024-08-05 18:30

import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="FanaCallRequest",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("table_id", models.CharField(max_length=20, unique=True)),
                (
                    "call_waiter_state",
                    models.CharField(
                        choices=[
                            ("pressed", "Pressed"),
                            ("not_pressed", "Not Pressed"),
                            ("in_progress", "In Progress"),
                        ],
                        default="not_pressed",
                        max_length=20,
                    ),
                ),
                (
                    "bring_bill_state",
                    models.CharField(
                        choices=[
                            ("pressed", "Pressed"),
                            ("not_pressed", "Not Pressed"),
                            ("in_progress", "In Progress"),
                        ],
                        default="not_pressed",
                        max_length=20,
                    ),
                ),
                (
                    "order_state",
                    models.CharField(
                        choices=[
                            ("pressed", "Pressed"),
                            ("not_pressed", "Not Pressed"),
                            ("in_progress", "In Progress"),
                        ],
                        default="not_pressed",
                        max_length=20,
                    ),
                ),
                (
                    "bring_water_state",
                    models.CharField(
                        choices=[
                            ("pressed", "Pressed"),
                            ("not_pressed", "Not Pressed"),
                            ("in_progress", "In Progress"),
                        ],
                        default="not_pressed",
                        max_length=20,
                    ),
                ),
                ("timestamp", models.DateTimeField(default=django.utils.timezone.now)),
                (
                    "handled_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
    ]
