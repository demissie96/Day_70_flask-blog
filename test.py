from functools import wraps
from flask import abort

#Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        id_number = 1
        #If id is not 1 then return abort with 403 error
        if id_number == 1:
            print(f'ID number is: {id_number}')
            return f(*args, **kwargs) 
            
        #Otherwise continue with the route function
        return print('Aborted')
                   
    return decorated_function


@admin_only
def printing():
    print('Szia')

printing()