from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from fanaCallSetup.models import FanaCallRequest
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from fanaCallSetup.models import FanaCallRequest
from fanaInsight.models import TableActivity, UserActivity
from django.http import JsonResponse
from django.utils import timezone
import json

global data_changed
data_changed = False

def signup_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('fanaDashboard')
    else:
        form = UserCreationForm()
    return render(request, 'fanaDashboard/signup.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('fanaDashboard')
    else:
        form = AuthenticationForm()
    return render(request, 'fanaDashboard/login.html', {'form': form})

@csrf_exempt
def handle_fana_call(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        combined_state = data.get('combined_state')
        table_id = data.get('table_id')
        user_id = data.get('user_id')  # Assuming user_id is passed in the request

        if combined_state and table_id:
            table_request, created = FanaCallRequest.objects.get_or_create(table_id=table_id)

            table_request.call_waiter_state = 'pressed' if combined_state[0] == '1' else 'released'
            table_request.bring_bill_state = 'pressed' if combined_state[1] == '1' else 'released'
            table_request.order_state = 'pressed' if combined_state[2] == '1' else 'released'
            table_request.bring_water_state = 'pressed' if combined_state[3] == '1' else 'released'

            table_request.timestamp = timezone.now()
            table_request.save()

            is_active = any(state == '1' for state in combined_state)
            user = User.objects.get(id=user_id) if user_id else None

            TableActivity.objects.create(
                table_id=table_id,
                is_active=is_active,
                user=user,
                timestamp=timezone.now()
            )

            if user:
                UserActivity.objects.create(
                    user=user,
                    is_active=is_active,
                    table=TableActivity.objects.filter(table_id=table_id).last(),
                    timestamp=timezone.now()
                )

            # Set user as inactive if the table becomes inactive
            if not is_active and user:
                UserActivity.objects.create(
                    user=user,
                    is_active=False,
                    table=None,
                    timestamp=timezone.now()
                )

            return JsonResponse({'status': 'success', 'message': 'Request logged successfully'})
        else:
            return JsonResponse({'status': 'error', 'message': 'Invalid data'}, status=400)
    else:
        return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=400)

@csrf_exempt
@login_required
def dashboard_view(request):
    global data_changed
    if request.method == 'POST':
        button_type = request.POST.get('button_type')
        table_id = request.POST.get('table_id')
        request_to_handle = FanaCallRequest.objects.get(table_id=table_id)

        if button_type == 'call_waiter':
            request_to_handle.call_waiter_state = 'in_progress'
        elif button_type == 'bring_bill':
            request_to_handle.bring_bill_state = 'in_progress'
        elif button_type == 'order':
            request_to_handle.order_state = 'in_progress'
        elif button_type == 'bring_water':
            request_to_handle.bring_water_state = 'in_progress'

        request_to_handle.handled_by = request.user
        request_to_handle.save()
        data_changed = True

        UserActivity.objects.create(
            user=request.user,
            is_active=True,
            table=TableActivity.objects.filter(table_id=table_id).last(),
            timestamp=timezone.now()
        )

        return redirect('fanaDashboard')

    requests = FanaCallRequest.objects.filter(
        call_waiter_state='pressed') | FanaCallRequest.objects.filter(
        bring_bill_state='pressed') | FanaCallRequest.objects.filter(
        order_state='pressed') | FanaCallRequest.objects.filter(
        bring_water_state='pressed')

    tables = {}
    for table_request in requests:
        if table_request.table_id not in tables:
            tables[table_request.table_id] = []
        if table_request.call_waiter_state == 'pressed':
            tables[table_request.table_id].append('Call Waiter')
        if table_request.bring_bill_state == 'pressed':
            tables[table_request.table_id].append('Bring Bill')
        if table_request.order_state == 'pressed':
            tables[table_request.table_id].append('Order')
        if table_request.bring_water_state == 'pressed':
            tables[table_request.table_id].append('Bring Water')

    tables = {table_id: requests for table_id, requests in tables.items() if requests}

    return render(request, 'fanaDashboard/dashboard.html', {'tables': tables})
